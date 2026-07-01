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
    #: Header printed above ``excerpt``. Checks may override to describe what the excerpt
    #: shows (e.g. "Latest excerpt (last 5 requests):").
    excerpt_label: str = "Latest excerpt:"


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
    excerpt_label: str = "Latest excerpt:",
) -> CheckResult:
    return CheckResult(number, title, Status.ISSUE, timestamp=timestamp,
                       excerpt=excerpt, details=details, excerpt_label=excerpt_label)


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


#: First dotted-quad in a log line. The client IP is the first IP-looking token in both
#: Apache layouts we see (combined puts it first; this bundle's access_log puts it after a
#: leading "[timestamp]" field) -- a date never contains a dotted quad, so the first match
#: is the client even when the timestamp precedes it. Positional split() would mis-read the
#: timestamp-first layout.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _client_ip(line: str) -> Optional[str]:
    m = _IPV4_RE.search(line)
    return m.group(0) if m else None


@register("2b", "Brute Force Attack - web server access_log")
def check_2b(ctx: Context) -> CheckResult:
    """Flag minute-windows where one source IP made >= WEB_PER_MINUTE_THRESHOLD requests."""
    title = "Brute Force Attack - web server access_log"
    if not ctx.reader.present("access_log"):
        return skipped("2b", title)
    windows: dict = defaultdict(list)  # (ip, minute_key) -> raw lines, oldest -> newest
    window_ts: dict = {}               # (ip, minute_key) -> latest UTC ts in that minute
    for line in ctx.reader.read_lines("access_log"):
        if not line.strip():
            continue
        ip = _client_ip(line)
        ts = parse_timestamp(line)
        if ip is None or ts is None:
            continue
        key = (ip, ts.strftime("%Y-%m-%d %H:%M"))
        windows[key].append(line.strip())
        window_ts[key] = ts  # last write wins -> newest ts within the minute
    offenders = [(key, lines) for key, lines in windows.items()
                 if len(lines) >= WEB_PER_MINUTE_THRESHOLD]
    if not offenders:
        return ok("2b", title)
    # Headline the most recent offending window, by timestamp.
    (ip, _minute), lines = max(offenders, key=lambda kv: window_ts[kv[0]])
    count = len(lines)
    disp_minute = _apache_minute(lines[-1]) or to_display(window_ts[(ip, _minute)])
    details = (f"{len(offenders)} minute-window(s) with >= {WEB_PER_MINUTE_THRESHOLD} "
               f"requests from a single IP detected.\n\n"
               f"Most recent: IP {ip} at {disp_minute} with {count} requests "
               f"in that minute.")
    excerpt = "\n".join(f"(access_log) {l}" for l in lines[-5:])
    return issue("2b", title, details=details, timestamp=None, excerpt=excerpt,
                 excerpt_label="Latest excerpt (last 5 requests):")


def _apache_minute(line: str) -> Optional[str]:
    """Minute label in the log's own local time (e.g. '11/Apr/2026:18:03'), or None.

    Uses the raw Apache stamp -- not the UTC-normalized datetime -- so the displayed
    minute matches the offset shown in the excerpt rather than being shifted to UTC.
    """
    m = _RE_APACHE.search(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group("stamp"), _APACHE_FMT)
    except ValueError:
        return None
    return dt.strftime("%d/%b/%Y:%H:%M")


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

_BANNER = "=" * 78

# Status banners for the plain-text block header. ISSUE/ERRORED shout; OK/SKIPPED don't.
_STATUS_BANNER = {
    Status.OK: "OK",
    Status.SKIPPED: "SKIPPED",
    Status.ISSUE: "*** ISSUE FOUND ***",
    Status.ERRORED: "*** ERRORED ***",
}


def _status_banner(status: str) -> str:
    return _STATUS_BANNER.get(status, status)


def _render_block(r: CheckResult, idx: int) -> list[str]:
    lines = [f"--- [{idx}] {r.number}) {r.title} ---",
             f"STATUS: {_status_banner(r.status)}"]
    if r.details:
        lines.extend(r.details.splitlines() or [""])
    # Checks that fold the time into their details (e.g. 2b) leave timestamp unset; only
    # show a standalone time line when an issue still carries one.
    if r.status == Status.ISSUE and r.timestamp is not None:
        lines.append(f"Latest event: {to_display(r.timestamp)}")
    # Render any non-empty excerpt, including the multi-line Info blocks (HA, sizing,
    # top recurring lines), not just ISSUE excerpts.
    if r.excerpt:
        lines.append(r.excerpt_label)
        lines.extend(f"  {ln}" for ln in r.excerpt.splitlines() or [""])
    return lines


def render_report(results: list[tuple[Check, CheckResult]]) -> str:
    """Render all results into the two-banner plain-text report (spec Section 4)."""
    out: list[str] = []
    # Global 1-based render index across the full order (1->[1], 2a->[2], 2b->[3], ...).
    idx_of = {id(res): i for i, (_chk, res) in enumerate(results, start=1)}

    def section(num: int, banner: str):
        out.append(_BANNER)
        out.append(banner)
        out.append(_BANNER)
        any_block = False
        for chk, res in results:
            if chk.section == num:
                out.extend(_render_block(res, idx_of[id(res)]))
                out.append("")
                any_block = True
        if not any_block:
            out.append("  (no checks)")
            out.append("")

    section(1, "ISSUES FOUND")
    section(2, "GENERAL INFORMATION")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# (7) HTML reporter -- the "diagnostic dossier". Same CheckResult data as the
# text reporter, rendered as one professional, self-contained page. CSS/JS are
# inline (stdlib only); web fonts load from Google Fonts with a system-font
# fallback, so the page still renders on an air-gapped box.
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
    parts.append(f'    <h3 class="card__title">{_esc(r.title)}</h3>')
    parts.append(f'    <span class="badge badge--{cls}"><span class="bdot"></span>{_esc(r.status)}</span>')
    parts.append('  </header>')
    if r.details:
        parts.append(f'  <div class="card__details">{_esc(r.details)}</div>')
    if r.status == Status.ISSUE:
        parts.append(f'  <div class="card__meta">Detected {_esc(to_display(r.timestamp))}</div>')
    if r.excerpt:
        parts.append('  <div class="card__excerpt">')
        parts.append(f'    <div class="excerpt__label">{_esc(r.excerpt_label)}</div>')
        parts.append(f'    <pre>{_esc(r.excerpt)}</pre>')
        parts.append('  </div>')
    parts.append('</article>')
    return "\n".join(parts)


# Inline stylesheet. Light is the default; dark is switched by the ``data-mode``
# attribute on <html> (set before paint by a tiny head script). Each mode just
# rebinds the CSS custom properties; status colours stay semantically consistent.
_HTML_STYLE = """\
:root {
  --canvas:#F4F5F7; --card:#FFFFFF; --ink:#14181F; --muted:#4B5563;
  --line:#E3E6EB; --accent:#1F49C4; --chip:#EEF1F6; --chip-ink:#3B4453;
  --issue:#C6362F; --errored:#9A5B00; --ok:#1E7A54; --skipped:#6B7480;
  --issue-soft:#FBEDEC; --errored-soft:#FAF1E1; --ok-soft:#E9F5EF; --skipped-soft:#EEF0F3;
  --shadow:0 1px 2px rgba(20,24,31,.05), 0 4px 14px rgba(20,24,31,.05);
  --font-display:"Space Grotesk",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-body:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --font-mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
html[data-mode="dark"] {
  --canvas:#0E141C; --card:#161E2A; --ink:#E9EDF3; --muted:#98A3B2;
  --line:#243040; --accent:#7FA0FF; --chip:#1E2836; --chip-ink:#AEB9C8;
  --issue:#F2705F; --errored:#E3A24A; --ok:#4FC08A; --skipped:#8A95A4;
  --issue-soft:#2A1A18; --errored-soft:#2A2417; --ok-soft:#14271E; --skipped-soft:#1B232E;
  --shadow:0 1px 2px rgba(0,0,0,.35), 0 6px 18px rgba(0,0,0,.4);
}
* { box-sizing:border-box; }
html { color-scheme:light dark; }
body {
  margin:0; padding:0 0 3rem; background:var(--canvas); color:var(--ink);
  font-family:var(--font-body); font-size:15px; line-height:1.55;
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
}
.wrap { max-width:960px; margin:0 auto; padding:2.5rem 1.5rem; }

/* masthead */
.masthead { display:flex; justify-content:space-between; align-items:flex-start;
  gap:1.5rem; flex-wrap:wrap; padding-bottom:1.15rem; border-bottom:1px solid var(--line); }
.brand-block { display:flex; flex-direction:column; gap:.2rem; }
.brand { font-family:var(--font-display); font-weight:700; font-size:1.75rem;
  letter-spacing:-.02em; line-height:1; color:var(--ink); }
.brand .dot { color:var(--accent); }
.tagline { color:var(--muted); font-size:.92rem; }
.meta-block { display:flex; flex-direction:column; align-items:flex-end; gap:.25rem; text-align:right; }
.meta-row { font-family:var(--font-mono); font-size:.76rem; color:var(--muted); word-break:break-all; }
.meta-row b { color:var(--ink); font-weight:500; }
.mode-toggle { margin-top:.55rem; background:var(--chip); color:var(--chip-ink);
  border:1px solid var(--line); border-radius:999px; font-family:var(--font-body);
  font-size:.78rem; padding:.35rem .85rem; cursor:pointer; }
.mode-toggle:hover { border-color:var(--accent); color:var(--accent); }

/* verdict banner (signature) */
.verdict { margin:1.9rem 0; background:var(--card); border:1px solid var(--line);
  border-radius:14px; box-shadow:var(--shadow); padding:1.5rem 1.6rem; }
.verdict__head { display:flex; align-items:center; gap:.8rem; }
.verdict__dot { width:.9rem; height:.9rem; border-radius:50%; flex:0 0 auto; margin-top:.15rem; }
.verdict__text { font-family:var(--font-display); font-weight:600; font-size:1.4rem;
  letter-spacing:-.01em; line-height:1.2; color:var(--ink); }
.verdict__sub { color:var(--muted); font-size:.9rem; margin-top:.2rem; }
.bar { display:flex; height:.6rem; border-radius:999px; overflow:hidden;
  margin:1.3rem 0 1.1rem; background:var(--chip); }
.seg { display:block; height:100%; }
.seg--ok{background:var(--ok);} .seg--skipped{background:var(--skipped);}
.seg--issue{background:var(--issue);} .seg--errored{background:var(--errored);}
.legend { display:flex; flex-wrap:wrap; gap:.55rem; }
.chip { display:inline-flex; align-items:center; gap:.5rem; background:transparent;
  border:1px solid var(--line); border-radius:999px; padding:.35rem .75rem;
  font-family:var(--font-body); font-size:.82rem; color:var(--ink); cursor:pointer; }
.chip:hover { border-color:var(--accent); }
.chip.off { opacity:.4; }
.chip .swatch { width:.6rem; height:.6rem; border-radius:2px; flex:0 0 auto; }
.chip .swatch--ok{background:var(--ok);} .chip .swatch--skipped{background:var(--skipped);}
.chip .swatch--issue{background:var(--issue);} .chip .swatch--errored{background:var(--errored);}
.chip .cnt { font-family:var(--font-mono); font-weight:600; }
.chip .lbl { color:var(--muted); }

/* section headings -- by name, no numbers */
.section { display:flex; align-items:baseline; gap:.65rem; margin:2.4rem 0 1.1rem;
  padding-bottom:.5rem; border-bottom:1px solid var(--line); }
.section h2 { font-family:var(--font-display); font-weight:600; font-size:1.2rem;
  letter-spacing:-.01em; margin:0; color:var(--ink); }
.section .count { font-family:var(--font-mono); font-size:.8rem; color:var(--muted); }
.empty { color:var(--muted); font-style:italic; margin:.5rem 0 0; }

/* finding cards */
.card { position:relative; background:var(--card); border:1px solid var(--line);
  border-radius:12px; box-shadow:var(--shadow); overflow:hidden;
  padding:1.05rem 1.25rem 1.05rem 1.4rem; margin-bottom:.85rem; }
.card::before { content:""; position:absolute; left:0; top:0; bottom:0; width:4px; }
.card--ok::before{background:var(--ok);} .card--skipped::before{background:var(--skipped);}
.card--issue::before{background:var(--issue);} .card--errored::before{background:var(--errored);}
.card__head { display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; }
.card__num { font-family:var(--font-mono); font-size:.76rem; font-weight:600;
  color:var(--chip-ink); background:var(--chip); border-radius:6px; padding:.15rem .45rem; }
.card__title { font-family:var(--font-body); font-weight:600; font-size:1rem;
  margin:0; flex:1 1 auto; color:var(--ink); }
.badge { display:inline-flex; align-items:center; gap:.4rem; font-family:var(--font-body);
  font-size:.72rem; font-weight:600; letter-spacing:.03em; text-transform:uppercase;
  border-radius:999px; padding:.24rem .6rem; }
.badge .bdot { width:.5rem; height:.5rem; border-radius:50%; background:currentColor; }
.badge--ok{color:var(--ok); background:var(--ok-soft);}
.badge--skipped{color:var(--skipped); background:var(--skipped-soft);}
.badge--issue{color:var(--issue); background:var(--issue-soft);}
.badge--errored{color:var(--errored); background:var(--errored-soft);}
.card__details { margin:.65rem 0 0; white-space:pre-wrap; color:var(--ink); }
.card__meta { margin:.55rem 0 0; font-family:var(--font-mono); font-size:.78rem; color:var(--muted); }
.card__excerpt { margin-top:.75rem; }
.excerpt__label { font-size:.72rem; color:var(--muted); margin-bottom:.35rem;
  text-transform:uppercase; letter-spacing:.06em; }
.card__excerpt pre { margin:0; padding:.75rem .85rem; background:var(--canvas);
  border:1px solid var(--line); border-radius:8px; font-family:var(--font-mono);
  font-size:.8rem; line-height:1.5; color:var(--ink); overflow-x:auto; white-space:pre; }

/* footer */
.foot { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:.78rem; font-family:var(--font-mono); }

/* status colour helpers */
.vd--ok{background:var(--ok);} .vd--skipped{background:var(--skipped);}
.vd--issue{background:var(--issue);} .vd--errored{background:var(--errored);}

/* status filtering: hiding a status adds a body class */
body.hide-OK .card[data-status="OK"],
body.hide-SKIPPED .card[data-status="SKIPPED"],
body.hide-ISSUE .card[data-status="ISSUE"],
body.hide-ERRORED .card[data-status="ERRORED"] { display:none; }

/* focus + motion */
button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
@media (prefers-reduced-motion: no-preference) {
  .seg { animation:grow .7s ease-out both; transform-origin:left; }
}
@keyframes grow { from { transform:scaleX(0); } to { transform:scaleX(1); } }

/* responsive */
@media (max-width:560px) {
  .wrap { padding:1.6rem 1.1rem; }
  .masthead { flex-direction:column; }
  .meta-block { align-items:flex-start; text-align:left; }
}
"""

# Runs before paint (in <head>) to set the colour mode with no flash: honours a
# saved choice, else the OS preference.
_HTML_MODE_BOOT = """\
(function () {
  try {
    var m = localStorage.getItem("faclog-mode");
    if (!m) m = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.setAttribute("data-mode", m);
  } catch (e) {
    document.documentElement.setAttribute("data-mode", "light");
  }
})();
"""

# Inline script (end of <body>): light/dark toggle (persisted) + status filters.
_HTML_SCRIPT = """\
(function () {
  var root = document.documentElement, body = document.body;
  var toggle = document.getElementById("mode-toggle");
  var label = document.getElementById("mode-label");
  function syncLabel() {
    var dark = root.getAttribute("data-mode") === "dark";
    if (label) label.textContent = dark ? "Light mode" : "Dark mode";
  }
  syncLabel();
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-mode") === "dark" ? "light" : "dark";
      root.setAttribute("data-mode", next);
      try { localStorage.setItem("faclog-mode", next); } catch (e) {}
      syncLabel();
    });
  }
  document.querySelectorAll(".chip[data-filter]").forEach(function (b) {
    b.addEventListener("click", function () {
      var hidden = body.classList.toggle("hide-" + b.getAttribute("data-filter"));
      b.classList.toggle("off", hidden);
      b.setAttribute("aria-pressed", (!hidden).toString());
    });
  });
})();
"""


def _verdict(counts: Counter) -> tuple[str, str, str]:
    """Derive (status-class, plain-language headline, sub-line) from the counts."""
    n_issue = counts.get(Status.ISSUE, 0)
    n_err = counts.get(Status.ERRORED, 0)
    total = sum(counts.values())
    if n_issue:
        verb = "needs" if n_issue == 1 else "need"
        noun = "issue" if n_issue == 1 else "issues"
        headline = f"{n_issue} {noun} {verb} attention"
        cls = "issue"
    elif n_err:
        noun = "check" if n_err == 1 else "checks"
        headline = f"{n_err} {noun} couldn't run"
        cls = "errored"
    else:
        headline = "All clear — no issues found"
        cls = "ok"
    plural = "check" if total == 1 else "checks"
    sub = f"{total} {plural} run against this bundle"
    return cls, headline, sub


def render_report_html(results: list[tuple[Check, CheckResult]], bundle_dir: str) -> str:
    """Render all results as one self-contained HTML page (the "diagnostic dossier")."""
    counts = Counter(res.status for _, res in results)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(counts.values()) or 1  # avoid divide-by-zero for the proportional bar

    vcls, headline, sub = _verdict(counts)

    order = (Status.ISSUE, Status.ERRORED, Status.OK, Status.SKIPPED)
    segments = "".join(
        f'<span class="seg seg--{_status_class(st)}" style="width:{counts[st] / total * 100:.4f}%"></span>'
        for st in order if counts.get(st, 0)
    )
    legend = "\n".join(
        f'<button class="chip" type="button" data-filter="{st}" aria-pressed="true">'
        f'<span class="swatch swatch--{_status_class(st)}"></span>'
        f'<span class="cnt">{counts.get(st, 0)}</span>'
        f'<span class="lbl">{st.lower()}</span></button>'
        for st in order
    )

    def section_html(num: int, name: str) -> str:
        blocks = [_html_block(res) for chk, res in results if chk.section == num]
        body = "\n".join(blocks) if blocks else '<p class="empty">No checks in this section.</p>'
        return (
            f'<div class="section"><h2>{_esc(name)}</h2>'
            f'<span class="count">{len(blocks)}</span></div>\n{body}'
        )

    return f"""<!DOCTYPE html>
<html lang="en" data-mode="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>faclog &middot; FortiAuthenticator diagnostic report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
{_HTML_STYLE}</style>
<script>{_HTML_MODE_BOOT}</script>
</head>
<body>
<div class="wrap">
<header class="masthead">
  <div class="brand-block">
    <div class="brand">faclog<span class="dot">.</span></div>
    <div class="tagline">FortiAuthenticator diagnostic report</div>
  </div>
  <div class="meta-block">
    <div class="meta-row">bundle <b>{_esc(bundle_dir)}</b></div>
    <div class="meta-row">generated <b>{_esc(generated)}</b></div>
    <button class="mode-toggle" id="mode-toggle" type="button" aria-label="Toggle colour theme">
      <span id="mode-label">Dark mode</span>
    </button>
  </div>
</header>

<section class="verdict">
  <div class="verdict__head">
    <span class="verdict__dot vd--{vcls}"></span>
    <div>
      <div class="verdict__text">{_esc(headline)}</div>
      <div class="verdict__sub">{_esc(sub)}</div>
    </div>
  </div>
  <div class="bar">{segments}</div>
  <div class="legend">
{legend}
  </div>
</section>

{section_html(1, "Issues Found")}
{section_html(2, "General Information")}

<footer class="foot">faclog &middot; generated {_esc(generated)}</footer>
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
