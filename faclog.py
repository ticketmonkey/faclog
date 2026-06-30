#!/usr/bin/env python3
"""FortiAuthenticator Log Analyzer.

A static health-check linter for FortiAuthenticator diagnostic bundles. It reads a
directory of heterogeneous component logs (Apache, kernel, RADIUS/LDAP, the ``wad``
proxy, NTP, custom Forti daemons) and reports *latent / general* issues -- conditions
that have caused problems across deployments -- rather than diagnosing one reported
fault.

This file holds both the framework and the detection checks:

    (0) Named thresholds          -- all tunables in one place.
    (1) Timestamp normalization   -- every component log into tz-aware UTC.
    (2) BundleReader              -- rotation-aware, missing-file-tolerant file access.
    (3) Check contract + runner   -- OK / SKIPPED / ISSUE / ERRORED, per-check isolation.
  (5/6) Detection checks          -- one @register'ed function per check/info.
    (4) Reporter + CLI            -- two banner sections, fixed check numbering.

The detection checks (spec Sections 5-6) implement Checks 1-11 and Info 1-5, reusing the
normalization layer, BundleReader, and the Occurrences summarizer.

Standard library only -- the bundle may be analyzed on an air-gapped support box. The
sole network use is Check 6, gated behind ``--check-network`` (default off), and it too
uses stdlib only.
"""

from __future__ import annotations

import argparse
import email.utils
import glob
import html
import os
import re
import socket
import sys
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# (0) Named thresholds -- every tunable lives here (spec Section 7).
# ---------------------------------------------------------------------------

#: Window for grouping repeated auth failures (Checks 1, 2a).
AUTH_WINDOW_SECONDS = 60

#: Check 2a -- number of "invalid user" failures within AUTH_WINDOW_SECONDS to flag.
AUTH_INVALID_USER_THRESHOLD = 20

#: Check 2b -- web requests per source IP per minute to flag (default low hundreds).
WEB_PER_MINUTE_THRESHOLD = 200

#: Check 10 -- disk usage percentage above which a watched mountpoint is flagged.
DISK_USAGE_PCT_THRESHOLD = 70

#: Check 10 -- only these mountpoints are evaluated; all others ignored.
DISK_WATCHED_MOUNTPOINTS = ("/var", "/data")

#: Check 4b -- max tolerated delta between local log time and HTTP Date: header.
CLOCK_DRIFT_SECONDS = 5

#: Lookback horizon for summarized checks (Checks 5, Info 5).
LOOKBACK_DAYS = 30

#: Check 6 -- per-probe network timeout, in seconds (only used with --check-network).
NETWORK_TIMEOUT_SECONDS = 5

#: Firmware version boundary that selects the resource-sizing table (Info 3).
FW_TABLE_BOUNDARY = (8, 0)

#: Check 1 -- max gap between the chap/mschap/double-space failures of one triple.
CHAP_TRIPLE_WINDOW_SECONDS = 5

#: Check 5 -- number of longest LDAP outages to list.
LDAP_TOP_OUTAGES = 10

#: Info 5 -- number of most-frequent normalized log lines to show.
INFO_TOP_RECURRING = 10

# Info 3 -- resource sizing tables, encoded as data (not inline conditionals).
# Each row: (max_users_upper_bound, required_cpus, required_ram_gb, required_disk_tb).
# Rows are ordered ascending; a licensed "Max users" count maps to the first row whose
# upper bound is >= the count. The final row's bound is the largest supported tier.
RESOURCE_TABLE_A = [  # FW < 8.0
    (500, 1, 4, 1),
    (2500, 2, 4, 1),
    (7500, 2, 8, 2),
    (25000, 4, 16, 2),
    (75000, 8, 32, 4),
    (250000, 16, 64, 4),
    (750000, 32, 128, 8),
    (2500000, 64, 256, 16),
    (7500000, 64, 512, 16),
]
RESOURCE_TABLE_B = [  # FW >= 8.0
    (2500, 8, 16, 1),
    (25000, 8, 16, 2),
    (75000, 8, 32, 4),
    (250000, 16, 64, 4),
    (750000, 32, 128, 8),
    (2500000, 64, 256, 16),
    (7500000, 64, 512, 16),
]


# ---------------------------------------------------------------------------
# (1) Timestamp normalization layer.
#
# Every check depends on this, so it is the foundation. Each component log uses its
# own timestamp format; this layer converts them all to a single tz-aware UTC
# ``datetime``. It must NEVER raise -- an unparseable timestamp degrades to ``None``
# and is rendered as ``(unknown time)``.
# ---------------------------------------------------------------------------

#: Rendered in place of a timestamp that could not be parsed.
UNKNOWN_TIME = "(unknown time)"

# ASSUMPTION (documented in one place, per spec Sections 2 & 8): when a timestamp
# carries no timezone/offset, it is interpreted as UTC. This applies to Forti
# ``time=`` values without an offset and to bare ``ctime`` strings.
ASSUMED_TZ = timezone.utc

# Forti key=value: date=2023-10-31 time=12:34:56+0000  (offset optional)
_RE_FORTI = re.compile(
    r"date=(?P<date>\d{4}-\d{2}-\d{2})\s+time=(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<offset>[+-]\d{4})?"
)

# Apache: [07/Apr/2024:22:21:43 +0200]
_RE_APACHE = re.compile(
    r"(?P<stamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})"
)

# ISO8601 with optional fractional seconds and offset:
#   2024-08-30T09:16:55.724382+05:30   or   2024-08-30T09:16:55
_RE_ISO = re.compile(
    r"(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
)

# HTTP Date: header (always UTC/GMT):  Fri, 30 Aug 2024 03:47:26 GMT
_RE_HTTP_DATE = re.compile(
    r"[A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT"
)

# Bare ctime from ps/top/fwinfo:  Thu Mar 19 19:24:20 2026
_RE_CTIME = re.compile(
    r"(?P<stamp>[A-Za-z]{3}\s+[A-Za-z]{3}\s+[ \d]\d\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
)

_APACHE_FMT = "%d/%b/%Y:%H:%M:%S %z"
_CTIME_FMT = "%a %b %d %H:%M:%S %Y"


def _as_utc(dt: datetime) -> datetime:
    """Attach the assumed timezone to a naive datetime, then normalize to UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ASSUMED_TZ)
    return dt.astimezone(timezone.utc)


def parse_timestamp(raw: str) -> Optional[datetime]:
    """Parse the first recognizable timestamp in ``raw`` into a tz-aware UTC datetime.

    Tries each known component-log format in turn (Forti key=value, Apache, ISO8601,
    HTTP ``Date:`` header, bare ctime). Returns ``None`` if nothing parses. Never
    raises -- callers rely on this to keep going past malformed lines.
    """
    if not raw:
        return None
    text = raw.strip()

    # Forti key=value
    m = _RE_FORTI.search(text)
    if m:
        stamp = f"{m.group('date')}T{m.group('time')}"
        offset = m.group("offset")
        try:
            dt = datetime.fromisoformat(stamp)
            if offset:
                # Normalize +HHMM -> +HH:MM for fromisoformat-compatible parsing.
                off = f"{offset[:3]}:{offset[3:]}"
                dt = datetime.fromisoformat(stamp + off)
            return _as_utc(dt)
        except ValueError:
            pass

    # Apache
    m = _RE_APACHE.search(text)
    if m:
        try:
            return _as_utc(datetime.strptime(m.group("stamp"), _APACHE_FMT))
        except ValueError:
            pass

    # HTTP Date: header (check before generic ISO so it isn't shadowed)
    m = _RE_HTTP_DATE.search(text)
    if m:
        try:
            dt = email.utils.parsedate_to_datetime(m.group(0))
            if dt is not None:
                return _as_utc(dt)
        except (TypeError, ValueError):
            pass

    # ISO8601 (with or without offset/fractional seconds)
    m = _RE_ISO.search(text)
    if m:
        stamp = m.group("stamp").replace(" ", "T")
        if stamp.endswith("Z"):
            stamp = stamp[:-1] + "+00:00"
        try:
            return _as_utc(datetime.fromisoformat(stamp))
        except ValueError:
            pass

    # Bare ctime
    m = _RE_CTIME.search(text)
    if m:
        # ctime may use a single-padded day ("Mar  9"); collapse double spaces first.
        candidate = re.sub(r"\s+", " ", m.group("stamp")).strip()
        try:
            return _as_utc(datetime.strptime(candidate, _CTIME_FMT))
        except ValueError:
            pass

    return None


def to_display(dt: Optional[datetime]) -> str:
    """Render a datetime for the report, or the ``(unknown time)`` sentinel."""
    if dt is None:
        return UNKNOWN_TIME
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# (2) File locator / reader.
#
# Handles rotation globs (access_log, access_log.1, ...) and treats a missing file as
# normal rather than an error.
# ---------------------------------------------------------------------------


def _rotation_sort_key(path: str):
    """Sort rotated logs oldest -> newest.

    Higher numeric suffix = older. The unsuffixed file is the newest, so it sorts
    last. e.g. access_log.2 < access_log.1 < access_log.
    """
    m = re.search(r"\.(\d+)$", path)
    suffix = int(m.group(1)) if m else -1
    # Newest (no suffix, suffix=-1) must sort last -> invert so larger suffix is smaller.
    return (-suffix, path)


class BundleReader:
    """Rotation-aware, missing-file-tolerant accessor for a diagnostic bundle.

    All methods are forgiving: a file that does not exist yields an empty result, and
    decoding uses ``errors="replace"`` so binary noise never aborts a read.
    """

    def __init__(self, root: str):
        self.root = root

    def find(self, name: str) -> list[str]:
        """Return existing paths for ``name`` and its rotations, oldest -> newest."""
        base = os.path.join(self.root, name)
        matches = set()
        if os.path.isfile(base):
            matches.add(base)
        # Numeric rotations: name.1, name.2, ... (and name.1.gz-style not expanded here).
        for p in glob.glob(base + ".*"):
            if re.search(r"\.\d+$", p):
                matches.add(p)
        return sorted(matches, key=_rotation_sort_key)

    def present(self, *names: str) -> bool:
        """True if at least one of the named files (or its rotations) exists."""
        return any(self.find(n) for n in names)

    def read_lines(self, name: str) -> list[str]:
        """All lines across ``name`` and its rotations, oldest -> newest. [] if absent."""
        lines: list[str] = []
        for path in self.find(name):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines.extend(fh.read().splitlines())
            except OSError:
                continue
        return lines

    def read_text(self, name: str) -> str:
        """Concatenated text of ``name`` and its rotations, oldest -> newest. '' if absent."""
        chunks: list[str] = []
        for path in self.find(name):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    chunks.append(fh.read())
            except OSError:
                continue
        return "\n".join(chunks)


# ---------------------------------------------------------------------------
# (3) Check contract + runner.
# ---------------------------------------------------------------------------


class Status:
    """The four terminal states of a check (spec Section 3.3 / 3.4)."""

    OK = "OK"            # check ran, found nothing
    SKIPPED = "SKIPPED"  # source file(s) absent
    ISSUE = "ISSUE"      # something to report
    ERRORED = "ERRORED"  # unexpected failure inside the check (isolated)


@dataclass
class CheckResult:
    """The structured outcome of a single check or info item.

    ``number`` is the fixed display label (e.g. ``"2a"``) and is independent of which
    checks run, so numbering never drifts when checks are skipped.
    """

    number: str
    title: str
    status: str
    timestamp: Optional[datetime] = None
    excerpt: str = ""
    details: str = ""


# Convenience constructors so check bodies stay terse.

def ok(number: str, title: str, details: str = "") -> CheckResult:
    return CheckResult(number, title, Status.OK, details=details or "no issues found")


def skipped(number: str, title: str, what: str = "file not present") -> CheckResult:
    return CheckResult(number, title, Status.SKIPPED, details=what)


def issue(
    number: str,
    title: str,
    details: str,
    timestamp: Optional[datetime] = None,
    excerpt: str = "",
) -> CheckResult:
    return CheckResult(number, title, Status.ISSUE, timestamp=timestamp,
                       excerpt=excerpt, details=details)


def errored(number: str, title: str, exc: BaseException) -> CheckResult:
    return CheckResult(number, title, Status.ERRORED,
                       details=f"{type(exc).__name__}: {exc}")


@dataclass
class Check:
    """A registry entry binding a fixed number/title to a check function.

    ``section`` is 1 (issues) or 2 (general information), controlling which banner the
    result is rendered under.
    """

    number: str
    title: str
    func: Callable[["Context"], CheckResult]
    section: int = 1


@dataclass
class Context:
    """Everything a check needs: the bundle reader and runtime options."""

    reader: BundleReader
    check_network: bool = False


# The registry. Order here is the canonical render order and MUST match the spec:
# Section 1 -> 1, 2a, 2b, 3, 4a, 4b, 5, 6, 7, 8, 9, 10, 11; Section 2 -> Info 1..5.
REGISTRY: list[Check] = []


def register(number: str, title: str, section: int = 1):
    """Decorator: add a check function to the registry with its fixed number/title."""
    def deco(func: Callable[[Context], CheckResult]):
        REGISTRY.append(Check(number, title, func, section))
        return func
    return deco


def run_check(check: Check, ctx: Context) -> CheckResult:
    """Run one check with full isolation.

    Any unexpected exception is caught and converted to an ``ERRORED`` result so a
    single malformed line or bad file can never abort the whole run (spec Section 3.4).
    """
    try:
        result = check.func(ctx)
        # Defensive: a check that forgets to set its number/title gets it from registry.
        if not result.number:
            result.number = check.number
        if not result.title:
            result.title = check.title
        return result
    except Exception as exc:  # noqa: BLE001 -- intentional catch-all for isolation
        sys.stderr.write(
            f"[faclog] check {check.number} raised: {traceback.format_exc()}"
        )
        return errored(check.number, check.title, exc)


# --- De-duplication / summarization helpers (spec Section 3.2) ---------------


@dataclass
class Occurrences:
    """Accumulator that collapses a recurring event to count + latest excerpt(s).

    Checks feed each matched event in via ``add``; the reporter then shows the total
    count and only the most-recent excerpt(s) by timestamp.
    """

    count: int = 0
    _latest: list[tuple[Optional[datetime], str]] = field(default_factory=list)
    keep: int = 1

    def add(self, ts: Optional[datetime], excerpt: str) -> None:
        self.count += 1
        self._latest.append((ts, excerpt))
        # Sort so unknown-time (None) entries sink to the front; keep the newest tail.
        self._latest.sort(key=lambda pair: (pair[0] is not None, pair[0] or datetime.min.replace(tzinfo=timezone.utc)))
        if len(self._latest) > self.keep:
            self._latest = self._latest[-self.keep:]

    @property
    def latest_timestamp(self) -> Optional[datetime]:
        return self._latest[-1][0] if self._latest else None

    @property
    def latest_excerpt(self) -> str:
        return "\n".join(e for _, e in self._latest)


# ---------------------------------------------------------------------------
# (5/6) Registered checks -- detection logic for spec Sections 5-6.
#
# One @register'ed function per check/info, each reusing the normalization layer,
# BundleReader, and Occurrences. run_check() isolates exceptions, so the bodies parse
# optimistically. Numbering is authoritative here (fixed render order).
# ---------------------------------------------------------------------------

_FORTI_EVENT = ("gui-db.log", "fac.logs")

# Forti key=value field extractor. Values are bare or double-quoted; quoted values may
# contain spaces (e.g. user="john doe", msg="authentication ...").
_FORTI_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

# A timestamp-bearing minimum used to sort "unknown time" (None) entries to the front.
_TS_MIN = datetime.min.replace(tzinfo=timezone.utc)


def _ts_sort_key(ts: Optional[datetime]):
    """Sort key putting unparseable (None) timestamps before real ones."""
    return (ts is not None, ts or _TS_MIN)


def _forti_fields(line: str) -> dict:
    """Parse a Forti key=value line into a dict. Quoted values keep their spaces."""
    fields: dict = {}
    for m in _FORTI_KV.finditer(line):
        fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


def _forti_lines(reader: BundleReader) -> list[str]:
    """Forti event-log lines. Prefer fac.logs (a superset of gui-db.log) to avoid
    double-counting events that appear in both."""
    if reader.present("fac.logs"):
        return reader.read_lines("fac.logs")
    return reader.read_lines("gui-db.log")


def _kernel_lines(reader: BundleReader) -> list[str]:
    """Combined kernel + syslog lines (distinct sources), oldest -> newest."""
    return reader.read_lines("kern.log") + reader.read_lines("syslog")


def _fmt_duration(seconds: float) -> str:
    """Human-readable HhMmSs duration."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m}m{s}s"
    if m:
        return f"{m}m{s}s"
    return f"{s}s"


def _probe_reachable(host: str, port: int) -> bool:
    """True if a TCP connection to host:port succeeds within NETWORK_TIMEOUT_SECONDS.
    Never raises -- any error means 'not reachable' (Check 6)."""
    try:
        with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT_SECONDS):
            return True
    except Exception:  # noqa: BLE001 -- a probe must never abort the run
        return False


def _cpu_core_count(reader: BundleReader) -> Optional[int]:
    """Core count = max CPU id + 1, read from the 'CPU' column of the top block in
    curproc. Returns None if the block/column is not found (Info 1, reused by Info 3)."""
    in_top = False
    cpu_idx: Optional[int] = None
    max_cpu = -1
    for line in reader.read_lines("curproc"):
        if "Current Processes (by CPU usage)" in line:
            in_top, cpu_idx = True, None
            continue
        if not in_top:
            continue
        cols = line.split()
        if cpu_idx is None:
            if "CPU" in cols:
                cpu_idx = cols.index("CPU")
            continue
        if len(cols) > cpu_idx and cols[cpu_idx].isdigit():
            max_cpu = max(max_cpu, int(cols[cpu_idx]))
    return max_cpu + 1 if max_cpu >= 0 else None


def _memory_gb(reader: BundleReader) -> dict:
    """Total / free / available RAM in GB from meminfo (Info 2, reused by Info 3)."""
    keymap = {"MemTotal": "total", "MemFree": "free", "MemAvailable": "available"}
    vals: dict = {}
    for line in reader.read_lines("meminfo"):
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m and m.group(1) in keymap:
            vals[keymap[m.group(1)]] = int(m.group(2)) / (1024 * 1024)  # kB -> GB
    return vals


@register("1", "Incorrect configuration (chap/mschap triple auth)")
def check_1(ctx: Context) -> CheckResult:
    """Detect one user failing chap + mschap + 'authentication  ' (double-space) auth
    three times at ~1s intervals -- the misconfigured-token signature."""
    title = "Incorrect configuration (chap/mschap triple auth)"
    if not ctx.reader.present(*_FORTI_EVENT):
        return skipped("1", title)
    # Per-user events, classified by which of the three msg variants the raw line shows.
    # The double-space "authentication  " form is the literal signature (an empty auth
    # method leaves two spaces); match it on the raw line since an unquoted msg value
    # would be truncated at the first space.
    per_user: dict = defaultdict(list)  # user -> [(ts, variant, line)]
    for line in _forti_lines(ctx.reader):
        if "authentication" not in line:
            continue
        if "authentication(chap)" in line:
            variant = "chap"
        elif "authentication(mschap)" in line:
            variant = "mschap"
        elif "authentication  " in line:
            variant = "blank"
        else:
            continue
        user = _forti_fields(line).get("user")
        if not user:
            continue
        per_user[user].append((parse_timestamp(line), variant, line.strip()))

    window = timedelta(seconds=CHAP_TRIPLE_WINDOW_SECONDS)
    affected: dict = {}  # user -> (latest_ts, excerpt)
    for user, evs in per_user.items():
        timed = sorted((e for e in evs if e[0] is not None), key=lambda e: e[0])
        for i in range(len(timed)):
            chosen: dict = {}
            for ts, variant, line in timed[i:]:
                if ts - timed[i][0] > window:
                    break
                chosen.setdefault(variant, (ts, line))
            if {"chap", "mschap", "blank"} <= set(chosen):
                latest = max(chosen.values(), key=lambda v: v[0])
                excerpt = "\n".join(chosen[v][1] for v in ("chap", "mschap", "blank"))
                affected[user] = (latest[0], excerpt)
    if not affected:
        return ok("1", title)
    latest_user = max(affected, key=lambda u: affected[u][0])
    ts, excerpt = affected[latest_user]
    users = ", ".join(sorted(affected))
    return issue("1", title,
                 details=f"{len(affected)} user(s) hit the chap/mschap/double-space "
                         f"triple within {CHAP_TRIPLE_WINDOW_SECONDS}s: {users}",
                 timestamp=ts, excerpt=excerpt)


@register("2a", "Brute force via auth logs")
def check_2a(ctx: Context) -> CheckResult:
    """Flag many 'invalid user' failures within AUTH_WINDOW_SECONDS."""
    title = "Brute force via auth logs"
    if not ctx.reader.present(*_FORTI_EVENT):
        return skipped("2a", title)
    events = []  # (ts, user, line)
    for line in _forti_lines(ctx.reader):
        if "invalid user" not in line.lower():
            continue
        ts = parse_timestamp(line)
        if ts is None:
            continue
        user = _forti_fields(line).get("user") or "(unknown)"
        events.append((ts, user, line.strip()))
    if len(events) < AUTH_INVALID_USER_THRESHOLD:
        return ok("2a", title)
    events.sort(key=lambda e: e[0])
    window = timedelta(seconds=AUTH_WINDOW_SECONDS)
    # Two-pointer sliding window over sorted timestamps to find the densest burst.
    start = 0
    best_count, best_span = 0, (0, 0)
    for end in range(len(events)):
        while events[end][0] - events[start][0] > window:
            start += 1
        if end - start + 1 > best_count:
            best_count = end - start + 1
            best_span = (start, end)
    if best_count < AUTH_INVALID_USER_THRESHOLD:
        return ok("2a", title)
    s, e = best_span
    burst = events[s:e + 1]
    sample = sorted({u for _, u, _ in burst})[:10]
    details = (f"{best_count} 'invalid user' failures within {AUTH_WINDOW_SECONDS}s "
               f"(threshold {AUTH_INVALID_USER_THRESHOLD}); window "
               f"{to_display(events[s][0])} -> {to_display(events[e][0])}; "
               f"users tried: {', '.join(sample)}")
    excerpt = "\n".join(l for _, _, l in burst[-3:])
    return issue("2a", title, details=details, timestamp=events[e][0], excerpt=excerpt)


@register("2b", "Brute force via web logs")
def check_2b(ctx: Context) -> CheckResult:
    """Flag source IPs exceeding WEB_PER_MINUTE_THRESHOLD requests per minute in access_log."""
    title = "Brute force via web logs"
    if not ctx.reader.present("access_log"):
        return skipped("2b", title)
    per_ip_minute: dict = defaultdict(Counter)  # ip -> Counter(minute_key)
    per_ip_total: Counter = Counter()
    per_ip_latest: dict = {}  # ip -> (ts, line)
    for line in ctx.reader.read_lines("access_log"):
        if not line.strip():
            continue
        ip = line.split()[0]
        ts = parse_timestamp(line)
        minute_key = ts.strftime("%Y-%m-%d %H:%M") if ts else None
        if minute_key is not None:
            per_ip_minute[ip][minute_key] += 1
        per_ip_total[ip] += 1
        if ts is not None and (ip not in per_ip_latest or ts >= per_ip_latest[ip][0]):
            per_ip_latest[ip] = (ts, line.strip())
    offenders = []  # (ip, peak_per_minute, total)
    for ip, minutes in per_ip_minute.items():
        peak = max(minutes.values(), default=0)
        if peak > WEB_PER_MINUTE_THRESHOLD:
            offenders.append((ip, peak, per_ip_total[ip]))
    if not offenders:
        return ok("2b", title)
    offenders.sort(key=lambda o: o[1], reverse=True)
    details = (f"{len(offenders)} source IP(s) exceeded {WEB_PER_MINUTE_THRESHOLD} "
               f"req/min: "
               + "; ".join(f"{ip} peak={peak}/min total={total}"
                           for ip, peak, total in offenders[:10]))
    latest = per_ip_latest.get(offenders[0][0])
    return issue("2b", title, details=details,
                 timestamp=latest[0] if latest else None,
                 excerpt=latest[1] if latest else "")


_REBOOT_RE = re.compile(
    r"recovered from an (?:unintended|unusual) (?:shutdown|reboot)"
    r"|\b(?:unintended|unusual)\b[^\n]*\breboot\b",
    re.I,
)


@register("3", "Unintended reboot")
def check_3(ctx: Context) -> CheckResult:
    """Detect 'recovered from an unintended/unusual shutdown/reboot' power-cycle messages."""
    title = "Unintended reboot"
    if not ctx.reader.present(*_FORTI_EVENT):
        return skipped("3", title)
    occ = Occurrences(keep=1)
    for line in _forti_lines(ctx.reader):
        if _REBOOT_RE.search(line):
            occ.add(parse_timestamp(line), line.strip())
    if occ.count == 0:
        return ok("3", title)
    return issue("3", title,
                 details=f"{occ.count} unintended/unusual reboot message(s)",
                 timestamp=occ.latest_timestamp, excerpt=occ.latest_excerpt)


_NTPD_RE = re.compile(r"NTPD adjusted time from (?P<a>.+?) to (?P<b>.+)", re.I)


@register("4a", "NTP instability")
def check_4a(ctx: Context) -> CheckResult:
    """Detect NTPD time adjustments that oscillate forward then back."""
    title = "NTP instability"
    if not ctx.reader.present(*_FORTI_EVENT):
        return skipped("4a", title)
    adjustments = []  # (event_ts, direction, line)
    for line in _forti_lines(ctx.reader):
        m = _NTPD_RE.search(line)
        if not m:
            continue
        a, b = parse_timestamp(m.group("a")), parse_timestamp(m.group("b"))
        if a is None or b is None:
            continue
        delta = (b - a).total_seconds()
        direction = (delta > 0) - (delta < 0)  # +1 forward, -1 back, 0 no change
        if direction != 0:
            adjustments.append((parse_timestamp(line), direction, line.strip()))
    # Oscillation = a direction change between consecutive (signed) adjustments.
    osc = []  # (event_ts, prev_line, line)
    prev_dir, prev_line = 0, None
    for ev_ts, direction, line in adjustments:
        if prev_dir != 0 and direction != prev_dir:
            osc.append((ev_ts, prev_line, line))
        prev_dir, prev_line = direction, line
    if not osc:
        return ok("4a", title)
    latest = max(osc, key=lambda o: _ts_sort_key(o[0]))
    return issue("4a", title,
                 details=f"{len(osc)} NTPD forward/back oscillation(s) detected",
                 timestamp=latest[0], excerpt=f"{latest[1]}\n{latest[2]}")


@register("4b", "System clock drift vs HTTP server time")
def check_4b(ctx: Context) -> CheckResult:
    """Compare local log time against the HTTP Date: header; flag deltas > CLOCK_DRIFT_SECONDS."""
    title = "System clock drift vs HTTP server time"
    if not ctx.reader.present("fgdfac.log"):
        return skipped("4b", title)
    # Walk the log; remember the most recent ISO8601 log-line timestamp (the line that
    # introduces a block). When a Date: header appears a few lines later inside that
    # block, both normalize to UTC -- a delta > threshold means the appliance clock is off.
    last_log_ts: Optional[datetime] = None
    last_log_line = ""
    occ = Occurrences(keep=1)
    worst = None  # (abs_delta, log_ts, excerpt)
    for line in ctx.reader.read_lines("fgdfac.log"):
        date_hdr = _RE_HTTP_DATE.search(line)
        if date_hdr:
            if last_log_ts is None:
                continue
            http_ts = parse_timestamp(date_hdr.group(0))
            if http_ts is None:
                continue
            delta = abs((http_ts - last_log_ts).total_seconds())
            if delta > CLOCK_DRIFT_SECONDS:
                excerpt = f"{last_log_line}\n    Date: {date_hdr.group(0)}"
                occ.add(last_log_ts, excerpt)
                if worst is None or delta > worst[0]:
                    worst = (delta, last_log_ts, excerpt)
        elif _RE_ISO.search(line):
            ts = parse_timestamp(line)
            if ts is not None:
                last_log_ts, last_log_line = ts, line.strip()
    if worst is None:
        return ok("4b", title)
    delta, log_ts, excerpt = worst
    return issue("4b", title,
                 details=f"clock drift up to {delta:.0f}s > {CLOCK_DRIFT_SECONDS}s between "
                         f"local log time and HTTP Date header ({occ.count} occurrence(s))",
                 timestamp=log_ts, excerpt=excerpt)


_LDAP_RE = re.compile(
    r"Remote server \(LDAP\) at (?P<ip>[\d.]+):(?P<port>\d+) has become "
    r"(?P<state>unreachable|available)",
    re.I,
)


@register("5", "Remote LDAP reachability")
def check_5(ctx: Context) -> CheckResult:
    """Pair LDAP unreachable->available transitions per IP; summarize over LOOKBACK_DAYS."""
    title = "Remote LDAP reachability"
    if not ctx.reader.present(*_FORTI_EVENT):
        return skipped("5", title)
    events: dict = defaultdict(list)  # ip -> [(ts, state)]
    all_ts = []
    for line in _forti_lines(ctx.reader):
        m = _LDAP_RE.search(line)
        if not m:
            continue
        ts = parse_timestamp(line)
        events[m.group("ip")].append((ts, m.group("state").lower()))
        if ts is not None:
            all_ts.append(ts)
    if not events:
        return ok("5", title)
    # "Last 30 days" is relative to the most recent event in the bundle (static,
    # air-gapped analysis -- there is no reliable "now").
    horizon = (max(all_ts) - timedelta(days=LOOKBACK_DAYS)) if all_ts else None

    def in_window(ts: Optional[datetime]) -> bool:
        return horizon is None or (ts is not None and ts >= horizon)

    per_ip_count: dict = {}
    outages = []  # (duration_seconds, ip, start_ts, end_ts)
    for ip, evs in events.items():
        windowed = [e for e in evs if in_window(e[0])]
        per_ip_count[ip] = len(windowed)
        timed = sorted((e for e in windowed if e[0] is not None), key=lambda e: e[0])
        pending = None
        for ts, state in timed:
            if state == "unreachable":
                pending = ts
            elif state == "available" and pending is not None:
                outages.append(((ts - pending).total_seconds(), ip, pending, ts))
                pending = None
    outages.sort(reverse=True)
    top = outages[:LDAP_TOP_OUTAGES]
    counts = "; ".join(f"{ip}: {c} event(s)" for ip, c in sorted(per_ip_count.items()))
    if top:
        outage_lines = "\n".join(
            f"    {ip}: {_fmt_duration(dur)} ({to_display(start)} -> {to_display(end)})"
            for dur, ip, start, end in top)
    else:
        outage_lines = "    (no completed unreachable->available outages in window)"
    return issue("5", title,
                 details=f"LDAP reachability events in last {LOOKBACK_DAYS}d -- {counts}",
                 timestamp=max(all_ts) if all_ts else None,
                 excerpt="Top outages:\n" + outage_lines)


_AH01914_RE = re.compile(
    r"AH01914: Configuring server (?P<fqdn>[\w.\-]+):(?P<port>\d+) for SSL")
_FQDN_PORT_RE = re.compile(
    r"\b(?P<fqdn>[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+):(?P<port>\d+)\b")


@register("6", "Webserver URL reachability")
def check_6(ctx: Context) -> CheckResult:
    """Extract FQDN:port from error_log; reachability is inverted (reachable = bad).
    Network probe gated behind --check-network (default off)."""
    title = "Webserver URL reachability"
    if not ctx.reader.present("error_log"):
        return skipped("6", title)
    text = ctx.reader.read_text("error_log")
    # Prefer the Apache SSL config line; fall back to any FQDN:port in the log.
    candidates: list = []
    seen: set = set()
    for regex in (_AH01914_RE, _FQDN_PORT_RE):
        for m in regex.finditer(text):
            key = (m.group("fqdn"), int(m.group("port")))
            if key not in seen:
                seen.add(key)
                candidates.append(key)
        if candidates:
            break
    if not candidates:
        return ok("6", title, details="no FQDN:port candidates found in error_log")
    listed = ", ".join(f"{h}:{p}" for h, p in candidates)
    if not ctx.check_network:
        return ok("6", title,
                  details=f"network probing off (--check-network); would test {listed}; "
                          f"not-tested")
    reachable = [f"{h}:{p}" for h, p in candidates if _probe_reachable(h, p)]
    if reachable:
        # Inverted semantics: externally reachable is the problem.
        return issue("6", title,
                     details=f"externally reachable (should not be): {', '.join(reachable)}",
                     excerpt=listed)
    return ok("6", title, details=f"probed {listed}; none reachable")


_OOM_PROC_RE = re.compile(r"Killed process \d+ \(([^)]+)\)|task=([\w./\-]+)")


@register("7", "Out-of-Memory events")
def check_7(ctx: Context) -> CheckResult:
    """Find 'oom-kill' / 'Out of memory: Killed process' in kernel/syslog."""
    title = "Out-of-Memory events"
    if not ctx.reader.present("kern.log", "syslog"):
        return skipped("7", title)
    occ = Occurrences(keep=1)
    procs: Counter = Counter()
    for line in _kernel_lines(ctx.reader):
        low = line.lower()
        if "oom-kill" not in low and "out of memory" not in low:
            continue
        m = _OOM_PROC_RE.search(line)
        if m:
            procs[m.group(1) or m.group(2)] += 1
        occ.add(parse_timestamp(line), line.strip())
    if occ.count == 0:
        return ok("7", title)
    names = (", ".join(f"{n} (x{c})" for n, c in procs.most_common(5))
             if procs else "(process name not parsed)")
    return issue("7", title,
                 details=f"{occ.count} OOM event(s); killed: {names}",
                 timestamp=occ.latest_timestamp, excerpt=occ.latest_excerpt)


_SEGFAULT_RE = re.compile(r"(?P<proc>[\w./\-]+)\[\d+\]: segfault")


@register("8", "Process crashes (segfault)")
def check_8(ctx: Context) -> CheckResult:
    """Find 'segfault' lines grouped by crashing process name."""
    title = "Process crashes (segfault)"
    if not ctx.reader.present("kern.log", "syslog"):
        return skipped("8", title)
    counts: Counter = Counter()
    per_proc: dict = defaultdict(lambda: Occurrences(keep=1))
    for line in _kernel_lines(ctx.reader):
        if "segfault" not in line:
            continue
        m = _SEGFAULT_RE.search(line)
        proc = m.group("proc").rsplit("/", 1)[-1] if m else "(unknown)"
        counts[proc] += 1
        per_proc[proc].add(parse_timestamp(line), line.strip())
    if not counts:
        return ok("8", title)
    summary = ", ".join(f"{p} (x{c})" for p, c in counts.most_common())
    latest_proc = max(per_proc, key=lambda p: _ts_sort_key(per_proc[p].latest_timestamp))
    occ = per_proc[latest_proc]
    return issue("8", title,
                 details=f"segfaults grouped by process: {summary}",
                 timestamp=occ.latest_timestamp, excerpt=occ.latest_excerpt)


_WAD_HTTP_RE = re.compile(r"Http response is not OK.*?http_code=(\d+)", re.I)
_HTTP_CODE_NOTES = {
    "0": "path broken / packet loss",
    "402": "payment / licensing / auth issue",
}


@register("9", "Bad HTTP responses in wad.log")
def check_9(ctx: Context) -> CheckResult:
    """Find 'Http response is not OK ... http_code=' grouped by http_code."""
    title = "Bad HTTP responses in wad.log"
    if not ctx.reader.present("wad.log"):
        return skipped("9", title)
    counts: Counter = Counter()
    per_code: dict = defaultdict(lambda: Occurrences(keep=1))
    for line in ctx.reader.read_lines("wad.log"):
        m = _WAD_HTTP_RE.search(line)
        if not m:
            continue
        code = m.group(1)
        counts[code] += 1
        per_code[code].add(parse_timestamp(line), line.strip())
    if not counts:
        return ok("9", title)
    parts = [f"http_code={code} ({_HTTP_CODE_NOTES.get(code, 'non-OK response')}) x{c}"
             for code, c in sorted(counts.items(), key=lambda kv: -kv[1])]
    latest_code = max(per_code, key=lambda k: _ts_sort_key(per_code[k].latest_timestamp))
    occ = per_code[latest_code]
    return issue("9", title, details="; ".join(parts),
                 timestamp=occ.latest_timestamp, excerpt=occ.latest_excerpt)


@register("10", "Disk usage")
def check_10(ctx: Context) -> CheckResult:
    """Flag usage > DISK_USAGE_PCT_THRESHOLD on watched mountpoints only."""
    title = "Disk usage"
    if not ctx.reader.present("disk_usage"):
        return skipped("10", title)
    flagged = []  # (mount, pct, raw_line)
    for line in ctx.reader.read_lines("disk_usage"):
        parts = line.split()
        if len(parts) < 2:
            continue
        mount = parts[-1]
        if mount not in DISK_WATCHED_MOUNTPOINTS:
            continue
        pct = next((int(t[:-1]) for t in parts
                    if t.endswith("%") and t[:-1].isdigit()), None)
        if pct is not None and pct > DISK_USAGE_PCT_THRESHOLD:
            flagged.append((mount, pct, line.strip()))
    if not flagged:
        return ok("10", title)
    flagged.sort(key=lambda f: f[1], reverse=True)
    details = "; ".join(f"{m} at {p}% (> {DISK_USAGE_PCT_THRESHOLD}%)"
                        for m, p, _ in flagged)
    return issue("10", title, details=details,
                 excerpt="\n".join(l for _, _, l in flagged))


_EXT4_DEV_RE = re.compile(r"EXT4-fs.*?\((?P<dev>[^)]+)\)")
_EXT4_CONT = ("error count since last fsck", "initial error at time",
              "last error at time")


@register("11", "EXT4 filesystem errors")
def check_11(ctx: Context) -> CheckResult:
    """Find multi-line 'EXT4-fs (<dev>): error' blocks grouped by device."""
    title = "EXT4 filesystem errors"
    if not ctx.reader.present("kern.log", "syslog"):
        return skipped("11", title)
    lines = _kernel_lines(ctx.reader)
    counts: Counter = Counter()
    per_dev: dict = {}  # dev -> (ts, block_text)
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if "EXT4-fs" in line and "error" in line.lower():
            m = _EXT4_DEV_RE.search(line)
            dev = m.group("dev") if m else "(unknown)"
            block = [line.strip()]
            ts = parse_timestamp(line)
            j = i + 1
            while j < n and any(k in lines[j] for k in _EXT4_CONT):
                block.append(lines[j].strip())
                j += 1
            counts[dev] += 1
            prev = per_dev.get(dev)
            if prev is None or _ts_sort_key(ts) >= _ts_sort_key(prev[0]):
                per_dev[dev] = (ts, "\n".join(block))
            i = j
        else:
            i += 1
    if not counts:
        return ok("11", title)
    summary = ", ".join(f"{d} (x{c})" for d, c in counts.most_common())
    latest_dev = max(per_dev, key=lambda d: _ts_sort_key(per_dev[d][0]))
    ts, block = per_dev[latest_dev]
    return issue("11", title, details=f"EXT4 errors by device: {summary}",
                 timestamp=ts, excerpt=block)


@register("Info 1", "CPU cores", section=2)
def info_1(ctx: Context) -> CheckResult:
    """Core count = max CPU id + 1, read from the top block in curproc."""
    title = "CPU cores"
    if not ctx.reader.present("curproc"):
        return skipped("Info 1", title)
    cores = _cpu_core_count(ctx.reader)
    if cores is None:
        return ok("Info 1", title, details="CPU column not found in curproc top block")
    return ok("Info 1", title, details=f"{cores} CPU core(s) (max CPU id + 1)")


@register("Info 2", "Memory", section=2)
def info_2(ctx: Context) -> CheckResult:
    """Report total / free / available RAM in GB from meminfo."""
    title = "Memory"
    if not ctx.reader.present("meminfo"):
        return skipped("Info 2", title)
    mem = _memory_gb(ctx.reader)
    if not mem:
        return ok("Info 2", title, details="no recognizable meminfo fields")
    parts = [f"{k}={mem[k]:.1f} GB" for k in ("total", "free", "available") if k in mem]
    return ok("Info 2", title, details="; ".join(parts))


def _fwinfo_field(text: str, *labels: str) -> Optional[str]:
    """Return the value after the first matching ``label:`` / ``label =`` in fwinfo."""
    for label in labels:
        m = re.search(rf"{label}\s*[:=]\s*(.+)", text, re.I)
        if m:
            return m.group(1).strip()
    return None


@register("Info 3", "Resource-spec compliance", section=2)
def info_3(ctx: Context) -> CheckResult:
    """Select sizing table by FW version (boundary FW_TABLE_BOUNDARY) and compare
    required vs actual CPU/RAM/Disk for licensed Max users."""
    title = "Resource-spec compliance"
    if not ctx.reader.present("fwinfo"):
        return skipped("Info 3", title)
    text = ctx.reader.read_text("fwinfo")
    model = _fwinfo_field(text, "Model")
    fw_raw = _fwinfo_field(text, "FW version", "Firmware version", "Firmware", "Version")
    users_raw = _fwinfo_field(text, "Max users", "Maximum users", "Licensed users")
    fw = None
    if fw_raw:
        mv = re.search(r"(\d+)\.(\d+)", fw_raw)
        if mv:
            fw = (int(mv.group(1)), int(mv.group(2)))
    max_users = None
    if users_raw:
        mu = re.search(r"(\d[\d,]*)", users_raw)
        if mu:
            max_users = int(mu.group(1).replace(",", ""))
    if fw is None or max_users is None:
        return ok("Info 3", title,
                  details=f"insufficient fwinfo (model={model}, fw={fw_raw}, "
                          f"max_users={users_raw})")
    table = RESOURCE_TABLE_A if fw < FW_TABLE_BOUNDARY else RESOURCE_TABLE_B
    table_name = "A (FW<8.0)" if fw < FW_TABLE_BOUNDARY else "B (FW>=8.0)"
    row = next((r for r in table if max_users <= r[0]), table[-1])
    req_cpu, req_ram, req_disk = row[1], row[2], row[3]
    actual_cpu = _cpu_core_count(ctx.reader)
    actual_ram = _memory_gb(ctx.reader).get("total")
    mismatches = []
    if actual_cpu is not None and actual_cpu < req_cpu:
        mismatches.append(f"CPU {actual_cpu} < required {req_cpu}")
    if actual_ram is not None and actual_ram + 0.5 < req_ram:
        mismatches.append(f"RAM {actual_ram:.1f}GB < required {req_ram}GB")
    block = "\n".join([
        f"Model: {model}",
        f"FW version: {fw_raw} -> table {table_name}",
        f"Max users: {max_users}",
        f"Required: {req_cpu} CPU / {req_ram} GB RAM / {req_disk} TB disk",
        f"Actual: CPU={actual_cpu if actual_cpu is not None else '?'}, "
        f"RAM={f'{actual_ram:.1f}GB' if actual_ram is not None else '?'}",
    ])
    status = Status.ISSUE if mismatches else Status.OK
    details = ("under-provisioned: " + "; ".join(mismatches)) if mismatches \
        else "meets sizing table"
    return CheckResult("Info 3", title, status, details=details, excerpt=block)


@register("Info 4", "HA operation", section=2)
def info_4(ctx: Context) -> CheckResult:
    """Print the HA info block; flag status/role errors."""
    title = "HA operation"
    if not ctx.reader.present("fwinfo"):
        return skipped("Info 4", title)
    block = []
    in_ha = False
    for line in ctx.reader.read_lines("fwinfo"):
        if re.search(r"HA info", line, re.I):
            in_ha, block = True, [line.strip()]
            continue
        if in_ha:
            if not line.strip():
                break
            block.append(line.strip())
    if not block:
        return ok("Info 4", title, details="no HA info block found")
    block_text = "\n".join(block)
    reasons = []
    if re.search(r"Status:\s*Status Error", block_text, re.I):
        reasons.append("Status: Status Error")
    if re.search(r"Role:\s*Determining", block_text, re.I) and \
            re.search(r"Enabled:\s*1", block_text):
        reasons.append("Role: Determining while Enabled=1")
    status = Status.ISSUE if reasons else Status.OK
    details = ("HA error: " + "; ".join(reasons)) if reasons else "HA info present"
    return CheckResult("Info 4", title, status, details=details, excerpt=block_text)


# Info 5 normalization: collapse volatile tokens so structurally-identical lines group.
_INFO5_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_INFO5_FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b")
_INFO5_ISO_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?")


def _normalize_logline(line: str) -> str:
    """Strip timestamps, IPs, and FQDNs so recurring lines collapse together."""
    s = _RE_FORTI.sub("date=<TS> time=<TS>", line)
    s = _INFO5_ISO_RE.sub("<TS>", s)
    s = _INFO5_IP_RE.sub("<IP>", s)
    s = _INFO5_FQDN_RE.sub("<FQDN>", s)
    return re.sub(r"\s+", " ", s).strip()


@register("Info 5", "Top recurring log lines", section=2)
def info_5(ctx: Context) -> CheckResult:
    """Show the 10 most frequent log lines over LOOKBACK_DAYS, after normalizing out
    timestamps/IPs/FQDNs."""
    title = "Top recurring log lines"
    if not ctx.reader.present("fac.logs"):
        return skipped("Info 5", title)
    stamped = [(parse_timestamp(l), l) for l in ctx.reader.read_lines("fac.logs")]
    times = [t for t, _ in stamped if t is not None]
    horizon = (max(times) - timedelta(days=LOOKBACK_DAYS)) if times else None
    counter: Counter = Counter()
    for ts, line in stamped:
        if horizon is not None and ts is not None and ts < horizon:
            continue
        norm = _normalize_logline(line)
        if norm:
            counter[norm] += 1
    if not counter:
        return ok("Info 5", title, details="no log lines in window")
    top = counter.most_common(INFO_TOP_RECURRING)
    block = "\n".join(f"{c:>6}  {text[:120]}" for text, c in top)
    return CheckResult("Info 5", title, Status.OK,
                       details=f"top {len(top)} recurring normalized lines "
                               f"(last {LOOKBACK_DAYS}d)",
                       excerpt=block)


# ---------------------------------------------------------------------------
# (4) Reporter.
# ---------------------------------------------------------------------------

_RULE = "-" * 78
_BANNER = "=" * 78


def _render_block(r: CheckResult) -> list[str]:
    lines = [_RULE, f"Check {r.number} - {r.title}", f"  Result    : {r.status}"]
    if r.details:
        detail_lines = r.details.splitlines() or [""]
        lines.append(f"  Details   : {detail_lines[0]}")
        lines.extend(f"              {extra}" for extra in detail_lines[1:])
    if r.status == Status.ISSUE:
        lines.append(f"  Timestamp : {to_display(r.timestamp)}")
    # Render any non-empty excerpt, including the multi-line Info blocks (HA, sizing,
    # top recurring lines), not just ISSUE excerpts.
    if r.excerpt:
        lines.append("  Log excerpt:")
        lines.extend(f"    {ln}" for ln in r.excerpt.splitlines() or [""])
    return lines


def render_report(results: list[tuple[Check, CheckResult]]) -> str:
    """Render all results into the two-banner plain-text report (spec Section 4)."""
    out: list[str] = []

    def section(num: int, banner: str):
        out.append(_BANNER)
        out.append(banner)
        out.append(_BANNER)
        any_block = False
        for chk, res in results:
            if chk.section == num:
                out.extend(_render_block(res))
                any_block = True
        if not any_block:
            out.append("  (no checks)")
        out.append("")

    section(1, "SECTION 1 - ISSUES FOUND")
    section(2, "SECTION 2 - GENERAL INFORMATION")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# (7) HTML reporter -- the "hacker interface". Same CheckResult data as the text
# reporter, rendered as one self-contained page (inline CSS + JS, no external
# assets, stdlib only -- safe for an air-gapped box).
# ---------------------------------------------------------------------------

# Map each status to a CSS class so colors are driven by per-theme variables.
_STATUS_CLASS = {
    Status.OK: "ok",
    Status.SKIPPED: "skipped",
    Status.ISSUE: "issue",
    Status.ERRORED: "errored",
}


def _status_class(status: str) -> str:
    return _STATUS_CLASS.get(status, "skipped")


def _esc(text: str) -> str:
    """Escape untrusted text (log excerpts/details come from arbitrary bundle files)."""
    return html.escape(text or "", quote=True)


def _html_block(r: CheckResult) -> str:
    """Render one check as a status-classed card, mirroring ``_render_block``."""
    cls = _status_class(r.status)
    parts = [f'<article class="card card--{cls}" data-status="{r.status}">']
    parts.append('  <header class="card__head">')
    parts.append(f'    <span class="card__num">{_esc(r.number)}</span>')
    parts.append(f'    <span class="card__title">{_esc(r.title)}</span>')
    parts.append(f'    <span class="badge badge--{cls}">{_esc(r.status)}</span>')
    parts.append('  </header>')
    if r.details:
        parts.append(f'  <div class="card__details">{_esc(r.details)}</div>')
    if r.status == Status.ISSUE:
        parts.append(f'  <div class="card__meta">timestamp: {_esc(to_display(r.timestamp))}</div>')
    if r.excerpt:
        parts.append(f'  <pre class="card__excerpt">{_esc(r.excerpt)}</pre>')
    parts.append('</article>')
    return "\n".join(parts)


# Inline stylesheet. Themes are switched by the ``data-theme`` attribute on <html>;
# each theme just rebinds the CSS custom properties.
_HTML_STYLE = """\
:root, html[data-theme="terminal"] {
  --bg:#020a02; --bg2:#0a160a; --fg:#39ff64; --dim:#1f7a35; --line:#114d20;
  --glow:0 0 6px rgba(57,255,100,.55); --accent:#39ff64;
  --ok:#39ff64; --skipped:#5a7a5a; --issue:#ff5b5b; --errored:#ffb347;
}
html[data-theme="amber"] {
  --bg:#0d0700; --bg2:#1a1000; --fg:#ffb000; --dim:#8a5e00; --line:#5a3d00;
  --glow:0 0 6px rgba(255,176,0,.55); --accent:#ffd060;
  --ok:#ffd060; --skipped:#8a6a2a; --issue:#ff6a3d; --errored:#ffe08a;
}
html[data-theme="neon"] {
  --bg:#070512; --bg2:#100a26; --fg:#00f0ff; --dim:#5a4b8a; --line:#3a2a66;
  --glow:0 0 8px rgba(0,240,255,.6); --accent:#ff3df0;
  --ok:#00ff9c; --skipped:#6a6a8a; --issue:#ff3df0; --errored:#ffd23d;
}
* { box-sizing:border-box; }
body {
  margin:0; padding:0 0 4rem; background:var(--bg); color:var(--fg);
  font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  font-size:14px; line-height:1.5; text-shadow:var(--glow);
}
/* CRT scanline overlay */
body::before {
  content:""; position:fixed; inset:0; pointer-events:none; z-index:9999;
  background:repeating-linear-gradient(rgba(0,0,0,0) 0 2px, rgba(0,0,0,.18) 2px 4px);
  mix-blend-mode:multiply;
}
.wrap { max-width:1000px; margin:0 auto; padding:1.5rem; }
header.top { border:1px solid var(--line); background:var(--bg2); padding:1rem 1.25rem; margin-bottom:1.25rem; }
.brand { font-size:2rem; font-weight:bold; letter-spacing:.15em; color:var(--accent); }
.brand .cursor { animation:blink 1s step-end infinite; }
@keyframes blink { 50% { opacity:0; } }
.subtitle { color:var(--dim); margin-top:.25rem; word-break:break-all; }
.controls { margin-top:.9rem; display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; }
.controls .label { color:var(--dim); margin-right:.25rem; }
button.btn {
  background:transparent; color:var(--fg); border:1px solid var(--line);
  font:inherit; text-shadow:var(--glow); padding:.25rem .6rem; cursor:pointer;
}
button.btn:hover { border-color:var(--accent); color:var(--accent); }
button.btn.active { border-color:var(--accent); color:var(--bg); background:var(--accent); text-shadow:none; }
.tiles { display:flex; flex-wrap:wrap; gap:.75rem; margin-bottom:1.25rem; }
.tile { flex:1 1 8rem; border:1px solid var(--line); background:var(--bg2); padding:.75rem 1rem; }
.tile .n { font-size:1.8rem; font-weight:bold; }
.tile .k { color:var(--dim); text-transform:uppercase; letter-spacing:.1em; font-size:.8rem; }
.tile--ok .n{color:var(--ok);} .tile--skipped .n{color:var(--skipped);}
.tile--issue .n{color:var(--issue);} .tile--errored .n{color:var(--errored);}
h2.section { border-bottom:1px solid var(--line); color:var(--accent); letter-spacing:.1em; margin:1.5rem 0 .75rem; padding-bottom:.3rem; }
.card { border:1px solid var(--line); border-left-width:4px; background:var(--bg2); padding:.75rem 1rem; margin-bottom:.6rem; }
.card--ok{border-left-color:var(--ok);} .card--skipped{border-left-color:var(--skipped);}
.card--issue{border-left-color:var(--issue);} .card--errored{border-left-color:var(--errored);}
.card__head { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; }
.card__num { color:var(--dim); }
.card__title { font-weight:bold; flex:1 1 auto; }
.badge { font-size:.75rem; padding:.1rem .5rem; border:1px solid currentColor; letter-spacing:.08em; }
.badge--ok{color:var(--ok);} .badge--skipped{color:var(--skipped);}
.badge--issue{color:var(--issue);} .badge--errored{color:var(--errored);}
.card__details { margin-top:.5rem; white-space:pre-wrap; }
.card__meta { margin-top:.35rem; color:var(--dim); }
.card__excerpt { margin:.5rem 0 0; padding:.6rem; background:var(--bg); border:1px solid var(--line);
  color:var(--dim); overflow-x:auto; white-space:pre; }
/* status filtering: hiding a status adds a body class */
body.hide-OK .card[data-status="OK"],
body.hide-SKIPPED .card[data-status="SKIPPED"],
body.hide-ISSUE .card[data-status="ISSUE"],
body.hide-ERRORED .card[data-status="ERRORED"] { display:none; }
"""

# Inline script: theme switching (persisted) + status-filter toggles. No dependencies.
_HTML_SCRIPT = """\
(function () {
  var root = document.documentElement, body = document.body;
  function setTheme(t) {
    root.setAttribute("data-theme", t);
    try { localStorage.setItem("faclog-theme", t); } catch (e) {}
    document.querySelectorAll("button[data-theme]").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-theme") === t);
    });
  }
  var saved = null;
  try { saved = localStorage.getItem("faclog-theme"); } catch (e) {}
  setTheme(saved || "terminal");
  document.querySelectorAll("button[data-theme]").forEach(function (b) {
    b.addEventListener("click", function () { setTheme(b.getAttribute("data-theme")); });
  });
  document.querySelectorAll("button[data-filter]").forEach(function (b) {
    b.addEventListener("click", function () {
      var cls = "hide-" + b.getAttribute("data-filter");
      var hidden = body.classList.toggle(cls);
      b.classList.toggle("active", !hidden);
    });
  });
})();
"""


def render_report_html(results: list[tuple[Check, CheckResult]], bundle_dir: str) -> str:
    """Render all results as one self-contained HTML page (the "hacker interface")."""
    counts = Counter(res.status for _, res in results)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    tiles = "\n".join(
        f'<div class="tile tile--{_status_class(st)}"><div class="n">{counts.get(st, 0)}</div>'
        f'<div class="k">{st.lower()}</div></div>'
        for st in (Status.ISSUE, Status.ERRORED, Status.OK, Status.SKIPPED)
    )

    filter_btns = "\n".join(
        f'<button class="btn active" data-filter="{st}">{st}</button>'
        for st in (Status.ISSUE, Status.ERRORED, Status.OK, Status.SKIPPED)
    )

    def section_html(num: int, banner: str) -> str:
        blocks = [_html_block(res) for chk, res in results if chk.section == num]
        body = "\n".join(blocks) if blocks else '<p class="card__meta">(no checks)</p>'
        return f'<h2 class="section">{_esc(banner)}</h2>\n{body}'

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="terminal">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>faclog report</title>
<style>
{_HTML_STYLE}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="brand">faclog<span class="cursor">_</span></div>
  <div class="subtitle">FortiAuthenticator log analysis &middot; bundle: {_esc(bundle_dir)} &middot; generated {_esc(generated)}</div>
  <div class="controls">
    <span class="label">theme:</span>
    <button class="btn" data-theme="terminal">terminal</button>
    <button class="btn" data-theme="amber">amber</button>
    <button class="btn" data-theme="neon">neon</button>
    <span class="label" style="margin-left:1rem;">filter:</span>
    {filter_btns}
  </div>
</header>
<div class="tiles">
{tiles}
</div>
{section_html(1, "SECTION 1 - ISSUES FOUND")}
{section_html(2, "SECTION 2 - GENERAL INFORMATION")}
</div>
<script>
{_HTML_SCRIPT}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Orchestration + CLI.
# ---------------------------------------------------------------------------


def run_all(bundle_dir: str, check_network: bool = False) -> list[tuple[Check, CheckResult]]:
    """Run every registered check against ``bundle_dir`` and return structured results."""
    ctx = Context(reader=BundleReader(bundle_dir), check_network=check_network)
    return [(chk, run_check(chk, ctx)) for chk in REGISTRY]


def analyze(bundle_dir: str, check_network: bool = False) -> str:
    """Run every registered check against ``bundle_dir`` and render the text report."""
    return render_report(run_all(bundle_dir, check_network=check_network))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="faclog",
        description="Static health-check linter for FortiAuthenticator diagnostic bundles.",
    )
    parser.add_argument(
        "bundle_dir", nargs="?", default=".",
        help="Directory containing the diagnostic bundle (default: current directory).",
    )
    parser.add_argument(
        "--check-network", action="store_true", default=False,
        help="Enable live reachability probing for Check 6 (default: off).",
    )
    parser.add_argument(
        "--html", action="store_true", default=False,
        help="Render the report as a self-contained HTML page (also inferred from a "
             ".html/.htm output path).",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Write the report to this path (default: stdout).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isdir(args.bundle_dir):
        sys.stderr.write(f"error: not a directory: {args.bundle_dir}\n")
        return 2
    as_html = args.html or (
        args.output is not None and args.output.lower().endswith((".html", ".htm"))
    )
    if as_html:
        report = render_report_html(
            run_all(args.bundle_dir, check_network=args.check_network),
            args.bundle_dir,
        )
    else:
        report = analyze(args.bundle_dir, check_network=args.check_network)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        sys.stdout.write(report + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
