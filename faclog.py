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

# --- Section 3 "Other Abnormalities" (A1-A3): heuristic analyses beyond the -------
#     specific Checks 1-11. All tunables live here like every other threshold.

#: A1 -- Forti ``level=`` values treated as elevated severity.
SEVERITY_LEVELS = ("error", "critical", "emergency", "alert", "panic")

#: A1 -- non-Forti log files swept for severity keywords (Forti events are always swept).
SEVERITY_SWEEP_FILES = ("fgdfac.log", "wad.log", "error_log", "kern.log", "syslog")

#: A1 -- number of top recurring severe signatures to list.
SEVERITY_TOP_SIGNATURES = 10

#: A1 -- a single normalized signature recurring at least this many times is flagged ISSUE.
SEVERITY_SIGNATURE_ISSUE_COUNT = 10

#: A2 -- the canonical bundle file inventory, for the coverage/timespan summary.
BUNDLE_FILE_INVENTORY = (
    "fac.logs", "gui-db.log", "access_log", "error_log", "fgdfac.log",
    "kern.log", "syslog", "wad.log", "disk_usage", "curproc", "meminfo", "fwinfo",
)

#: A3 -- number of top auth-failure reasons to list.
AUTH_FAIL_TOP = 10

#: A3 -- total Apache 5xx responses at/above which the breakdown is flagged ISSUE.
HTTP_5XX_ISSUE_COUNT = 25

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
# (5c) Section 3 -- "Other Abnormalities" (A1-A3).
#
# Heuristic, catch-all analyses that surface anomalies *beyond* the specific
# Checks 1-11: a general severity sweep, a coverage/timespan summary, and an
# auth/HTTP breakdown. Each reuses the normalization layer, BundleReader, and
# Occurrences, and each still always emits OK/SKIPPED/ISSUE/ERRORED.
# ---------------------------------------------------------------------------

# A1 severity keyword (word-boundary) -- covers Apache [error], kernel, wad, fgdfac,
# and Forti "level=error" lines (the level value is caught by the same word match).
_SEVERITY_RE = re.compile(
    r"\b(?:error|critical|crit|panic|fatal|emerg(?:ency)?|alert|fail(?:ed|ure)?)\b", re.I)

# Lines a specific check already owns are excluded from the A1 sweep so it never
# double-counts. These reuse the exact predicates those checks use, so A1 stays in sync.
_A1_CLAIMED_RE = (_REBOOT_RE, _NTPD_RE, _SEGFAULT_RE, _WAD_HTTP_RE)
_A1_CLAIMED_SUB = ("oom-kill", "out of memory", "invalid user")


def _a1_is_severe(line: str) -> bool:
    """True if the line's Forti ``level=`` is elevated or it hits the severity regex."""
    if "level=" in line:
        level = _forti_fields(line).get("level")
        if level and level.lower() in SEVERITY_LEVELS:
            return True
    return bool(_SEVERITY_RE.search(line))


def _a1_claimed(line: str) -> bool:
    """True if a specific check (2a/3/4a/7/8/9/11) already itemizes this line."""
    low = line.lower()
    if any(sub in low for sub in _A1_CLAIMED_SUB):
        return True
    if "EXT4-fs" in line and "error" in low:  # check_11's own guard
        return True
    return any(rgx.search(line) for rgx in _A1_CLAIMED_RE)


@register("A1", "Elevated log severity sweep", section=3)
def check_a1(ctx: Context) -> CheckResult:
    """Sweep all message logs for elevated-severity lines, excluding those a specific
    check already owns, and rank the recurring signatures (via _normalize_logline)."""
    title = "Elevated log severity sweep"
    sources = list(_FORTI_EVENT) + list(SEVERITY_SWEEP_FILES)
    if not ctx.reader.present(*sources):
        return skipped("A1", title)
    lines = list(_forti_lines(ctx.reader))
    for name in SEVERITY_SWEEP_FILES:
        lines.extend(ctx.reader.read_lines(name))
    counter: Counter = Counter()
    per_sig: dict = defaultdict(lambda: Occurrences(keep=1))
    scanned = 0
    for line in lines:
        if not line.strip() or not _a1_is_severe(line) or _a1_claimed(line):
            continue
        sig = _normalize_logline(line)
        if not sig:
            continue
        scanned += 1
        counter[sig] += 1
        per_sig[sig].add(parse_timestamp(line), line.strip())
    if not counter:
        return ok("A1", title, details="no unclaimed elevated-severity lines found")
    top = counter.most_common(SEVERITY_TOP_SIGNATURES)
    block = "\n".join(f"{c:>6}  {sig[:120]}" for sig, c in top)
    label = f"Top {len(top)} recurring severe signatures:"
    details = (f"{scanned} elevated-severity line(s) across {len(counter)} distinct "
               f"signature(s), excluding events already itemized by Checks 1-11")
    top_sig, top_count = top[0]
    if top_count >= SEVERITY_SIGNATURE_ISSUE_COUNT:
        return issue("A1", title,
                     details=details + f"; top signature recurs x{top_count} "
                             f"(>= {SEVERITY_SIGNATURE_ISSUE_COUNT})",
                     timestamp=per_sig[top_sig].latest_timestamp,
                     excerpt=block, excerpt_label=label)
    return CheckResult("A1", title, Status.OK, details=details,
                       excerpt=block, excerpt_label=label)


@register("A2", "Log coverage & timespan", section=3)
def check_a2(ctx: Context) -> CheckResult:
    """Summarize what was analyzed: which bundle files are present, their line counts,
    and each file's earliest -> latest timestamp span. Always informational."""
    title = "Log coverage & timespan"
    present_rows = []  # (name, line_count, min_ts, max_ts)
    absent = []
    all_min = all_max = None
    for name in BUNDLE_FILE_INVENTORY:
        if not ctx.reader.find(name):
            absent.append(name)
            continue
        lines = ctx.reader.read_lines(name)
        times = [t for t in (parse_timestamp(l) for l in lines) if t is not None]
        lo = min(times) if times else None
        hi = max(times) if times else None
        if lo is not None:
            all_min = lo if all_min is None else min(all_min, lo)
            all_max = hi if all_max is None else max(all_max, hi)
        present_rows.append((name, len(lines), lo, hi))
    width = max((len(n) for n, *_ in present_rows), default=0)
    out = []
    for name, count, lo, hi in present_rows:
        span = (f"{to_display(lo)} -> {to_display(hi)}" if lo is not None
                else "(no parseable timestamps)")
        out.append(f"present  {name:<{width}}  {count:>7} lines   {span}")
    if absent:
        out.append("")
        out.append("absent:  " + ", ".join(absent))
    span_note = (f"; overall span {to_display(all_min)} -> {to_display(all_max)}"
                 if all_min is not None else "")
    details = (f"{len(present_rows)} of {len(BUNDLE_FILE_INVENTORY)} expected bundle "
               f"files present{span_note}")
    return CheckResult("A2", title, Status.OK, details=details,
                       excerpt="\n".join(out) if out else "(no bundle files found)",
                       excerpt_label="Coverage:")


# A3: pull the HTTP status token that follows the quoted Apache request line.
_A3_ACCESS_STATUS_RE = re.compile(r'"[A-Z]+[^"]*"\s+(\d{3})\b')
# A3: an authentication line counts as a failure if it carries one of these words.
_A3_AUTH_FAIL_RE = re.compile(
    r"\b(?:fail(?:ed|ure)?|denied|reject(?:ed)?|lockout|locked|expired)\b", re.I)


@register("A3", "Auth & HTTP breakdown", section=3)
def check_a3(ctx: Context) -> CheckResult:
    """Two heuristic breakdowns: Forti authentication-failure reasons (beyond the 2a
    brute-force burst) and the Apache access_log HTTP status distribution."""
    title = "Auth & HTTP breakdown"
    have_forti = ctx.reader.present(*_FORTI_EVENT)
    have_access = ctx.reader.present("access_log")
    if not have_forti and not have_access:
        return skipped("A3", title)

    # Sub-A: Forti auth-failure reasons.
    reasons: Counter = Counter()
    auth_total = 0
    latest_fail = Occurrences(keep=1)
    if have_forti:
        for line in _forti_lines(ctx.reader):
            low = line.lower()
            if "authentication" not in low and "login" not in low:
                continue
            if not _A3_AUTH_FAIL_RE.search(line):
                continue
            fields = _forti_fields(line)
            raw = fields.get("msg") or fields.get("status") or fields.get("action") or ""
            reasons[_normalize_logline(raw)[:80] or "(unspecified)"] += 1
            auth_total += 1
            latest_fail.add(parse_timestamp(line), line.strip())

    # Sub-B: Apache HTTP status distribution.
    codes: Counter = Counter()
    classes: Counter = Counter()
    if have_access:
        for line in ctx.reader.read_lines("access_log"):
            m = _A3_ACCESS_STATUS_RE.search(line)
            if m:
                code = m.group(1)
                codes[code] += 1
                classes[f"{code[0]}xx"] += 1
    n_4xx = sum(c for code, c in codes.items() if code.startswith("4"))
    n_5xx = sum(c for code, c in codes.items() if code.startswith("5"))

    out = []
    if have_forti:
        if reasons:
            out.append("Auth failures by reason:")
            out.extend(f"  {c:>6}  {r}" for r, c in reasons.most_common(AUTH_FAIL_TOP))
        else:
            out.append("Auth failures by reason: none found")
    else:
        out.append("Auth failures by reason: (fac.logs/gui-db.log not present)")
    out.append("")
    if have_access:
        if codes:
            out.append("HTTP status distribution:")
            out.extend(f"  {c:>6}  {cls}" for cls, c in sorted(classes.items()))
            out.append("  top codes: " + ", ".join(
                f"{code} x{c}" for code, c in codes.most_common(AUTH_FAIL_TOP)))
        else:
            out.append("HTTP status distribution: no status codes parsed")
    else:
        out.append("HTTP status distribution: (access_log not present)")

    details = (f"{auth_total} auth failure(s)"
               + (f" across {len(reasons)} reason(s)" if reasons else "")
               + f"; HTTP 4xx={n_4xx}, 5xx={n_5xx}")
    if n_5xx >= HTTP_5XX_ISSUE_COUNT:
        return issue("A3", title,
                     details=details + f" (5xx >= {HTTP_5XX_ISSUE_COUNT})",
                     timestamp=None, excerpt="\n".join(out), excerpt_label="Breakdown:")
    return CheckResult("A3", title, Status.OK, details=details,
                       excerpt="\n".join(out), excerpt_label="Breakdown:")


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
    section(3, "OTHER ABNORMALITIES")
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
    """Render one check as a status-toned HUD card, mirroring the design's CheckCard."""
    cls = _status_class(r.status)
    parts = [f'<article class="card card--{cls}" data-status="{r.status}">']
    parts.append('  <span class="card__bar"></span>')
    parts.append('  <span class="card__corner card__corner--tl"></span>')
    parts.append('  <span class="card__corner card__corner--br"></span>')
    parts.append('  <div class="card__pad">')
    parts.append('    <div class="card__head">')
    parts.append(f'      <span class="card__num">{_esc(r.number)}</span>')
    parts.append(f'      <h3 class="card__title">{_esc(r.title)}</h3>')
    parts.append(f'      <span class="card__badge"><span class="card__badge-dot"></span>{_esc(r.status)}</span>')
    parts.append('    </div>')
    if r.details:
        parts.append(f'    <p class="card__details">{_esc(r.details)}</p>')
    if r.status == Status.ISSUE and r.timestamp is not None:
        parts.append(
            '    <div class="card__meta"><span class="card__meta-arrow">&#9656;</span>'
            f'DETECTED {_esc(to_display(r.timestamp))}</div>'
        )
    if r.excerpt:
        parts.append('    <div class="excerpt">')
        parts.append('      <div class="excerpt__head">')
        parts.append('        <span class="excerpt__dot"></span>')
        parts.append(f'        <span class="excerpt__label">{_esc(r.excerpt_label)}</span>')
        parts.append('        <span class="excerpt__tag">log stream</span>')
        parts.append('      </div>')
        parts.append(f'      <pre class="excerpt__body">{_esc(r.excerpt)}</pre>')
        parts.append('    </div>')
    parts.append('  </div>')
    parts.append('</article>')
    return "\n".join(parts)


# Inline stylesheet. Light is the default; dark is switched by the ``data-mode``
# attribute on <html> (set before paint by a tiny head script). Each mode just
# rebinds the CSS custom properties; status colours stay semantically consistent.
_HTML_STYLE = """\
:root {
  --bg:#0a1512; --ink:#e4f1ec; --teal:#22d3c5;
  --font-display:'Chivo',system-ui,-apple-system,'Segoe UI',sans-serif;
  --font-body:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
* { box-sizing:border-box; }
html, body { margin:0; padding:0; background:#0a1512; }
body {
  background-color:#0a1512;
  background-image:linear-gradient(rgba(110,190,170,0.045) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(110,190,170,0.045) 1px,transparent 1px);
  background-size:44px 44px;
  font-family:var(--font-body); color:var(--ink);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
}
.page { position:relative; min-height:100vh; overflow:hidden; }
.page__glow { position:absolute; inset:0 0 auto 0; height:340px; pointer-events:none;
  background:radial-gradient(80% 100% at 50% 0%, rgba(46,230,182,0.08), transparent 70%); }
.wrap { position:relative; z-index:1; max-width:1060px; margin:0 auto; padding:34px 30px 90px; }

/* shared hexagon */
.clip-hex { clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%); }
.hex { position:relative; flex:none; }
.hex__core { position:absolute; inset:0; display:grid; place-items:center; }
.hex--logo { width:34px; height:38px; }
.hex--logo .hex__edge { position:absolute; inset:0; background:var(--teal);
  box-shadow:0 0 16px -2px rgba(46,230,182,0.7); }
.hex--logo .hex__face { position:absolute; inset:2px; background:#0a1512; }
.hex--logo .hex__pip { width:9px; height:10px; background:var(--teal); }
.hex--verdict { width:66px; height:74px; }
.hex--verdict .hex__edge { position:absolute; inset:0; background:var(--vtone);
  box-shadow:0 0 30px -4px var(--vtone); }
.hex--verdict .hex__face { position:absolute; inset:2px; background:#0e1a17; }
.hex__count { font-family:var(--font-display); font-weight:900; font-size:1.75rem; color:var(--vtone); }

/* command bar */
.cmdbar { position:sticky; top:0; z-index:20; display:flex; justify-content:space-between;
  align-items:center; gap:20px; flex-wrap:wrap; padding:16px 30px;
  background:rgba(10,21,18,0.82); -webkit-backdrop-filter:blur(10px); backdrop-filter:blur(10px);
  border-bottom:1px solid rgba(110,190,170,0.14); }
.cmdbar__brandwrap { display:flex; align-items:center; gap:15px; }
.cmdbar__id { display:flex; flex-direction:column; gap:3px; }
.cmdbar__eyebrow { font-family:var(--font-mono); font-size:0.6rem; font-weight:500;
  letter-spacing:0.34em; text-transform:uppercase; color:#6d827c; }
.cmdbar__brand { font-family:var(--font-display); font-weight:900; font-size:1.32rem;
  letter-spacing:-0.02em; line-height:1; color:var(--ink); }
.cmdbar__cursor { color:var(--teal); }
.cmdbar__right { display:flex; align-items:center; gap:26px; flex-wrap:wrap; }
.cmdbar__meta { display:flex; flex-direction:column; gap:4px; text-align:right; }
.cmdbar__meta-row { font-family:var(--font-mono); font-size:0.7rem; color:#6d827c;
  letter-spacing:0.03em; word-break:break-all; }
.cmdbar__meta-row span { color:#c6ded4; }
.cmdbar__status { display:inline-flex; align-items:center; gap:8px; font-family:var(--font-mono);
  font-size:0.66rem; letter-spacing:0.14em; text-transform:uppercase; color:var(--teal);
  border:1px solid rgba(46,230,182,0.3); border-radius:3px; padding:6px 11px; background:rgba(46,230,182,0.07); }
.cmdbar__status-dot { width:7px; height:7px; background:var(--teal); box-shadow:0 0 8px 0 var(--teal);
  transform:rotate(45deg); animation:fac-blink 2s ease-in-out infinite; }

/* verdict / HUD panel */
.verdict { position:relative; margin-bottom:20px; border:1px solid rgba(110,190,170,0.16);
  border-radius:6px; padding:30px 32px; overflow:hidden;
  background:linear-gradient(180deg, rgba(19,36,32,0.9), rgba(13,26,23,0.9)); }
.vc { position:absolute; width:16px; height:16px; }
.vc--tl { left:12px; top:12px; border-left:1px solid var(--vtone); border-top:1px solid var(--vtone); }
.vc--tr { right:12px; top:12px; border-right:1px solid var(--vtone); border-top:1px solid var(--vtone); }
.vc--bl { left:12px; bottom:12px; border-left:1px solid var(--vtone); border-bottom:1px solid var(--vtone); }
.vc--br { right:12px; bottom:12px; border-right:1px solid var(--vtone); border-bottom:1px solid var(--vtone); }
.verdict__head { display:flex; align-items:center; gap:24px; flex-wrap:wrap; }
.verdict__body { flex:1 1 260px; min-width:230px; }
.verdict__eyebrow { font-family:var(--font-mono); font-size:0.62rem; letter-spacing:0.3em;
  text-transform:uppercase; color:#6d827c; margin-bottom:8px; }
.verdict__headline { font-family:var(--font-display); font-weight:700; font-size:1.85rem;
  letter-spacing:-0.015em; line-height:1.1; color:var(--ink); text-transform:uppercase; }
.verdict__sub { margin-top:8px; font-family:var(--font-mono); font-size:0.76rem;
  color:#8aa39c; letter-spacing:0.02em; }
.bar { display:flex; height:8px; border-radius:2px; overflow:hidden; margin:24px 0 15px;
  background:rgba(110,190,170,0.1); }
.seg { display:block; height:100%; transform-origin:left;
  animation:fac-grow .85s cubic-bezier(0.16,1,0.3,1) both; }
.seg--ok { background:#34e0a0; box-shadow:0 0 10px -1px #34e0a0; }
.seg--issue { background:#ff6a8a; box-shadow:0 0 10px -1px #ff6a8a; }
.seg--errored { background:#ffcf5c; box-shadow:0 0 10px -1px #ffcf5c; }
.seg--skipped { background:#6d8380; box-shadow:0 0 10px -1px #6d8380; }
.legend { display:flex; flex-wrap:wrap; gap:9px; }
.chip { display:inline-flex; align-items:center; gap:9px; background:rgba(110,190,170,0.05);
  border:1px solid rgba(110,190,170,0.16); border-radius:3px; padding:7px 13px; cursor:pointer;
  opacity:1; transition:opacity .18s; font-family:var(--font-mono); }
.chip.off { opacity:.36; }
.chip__swatch { width:8px; height:8px; transform:rotate(45deg); flex:none; }
.chip__cnt { font-weight:700; font-size:0.8rem; color:var(--ink); }
.chip__lbl { font-size:0.62rem; letter-spacing:0.16em; text-transform:uppercase; color:#8aa39c; }
.sw--ok { background:#34e0a0; box-shadow:0 0 8px -1px #34e0a0; }
.sw--issue { background:#ff6a8a; box-shadow:0 0 8px -1px #ff6a8a; }
.sw--errored { background:#ffcf5c; box-shadow:0 0 8px -1px #ffcf5c; }
.sw--skipped { background:#6d8380; box-shadow:0 0 8px -1px #6d8380; }

/* telemetry strip */
.telem { display:grid; grid-template-columns:repeat(4,1fr); gap:11px; margin-bottom:38px; }
.stat { position:relative; border:1px solid rgba(110,190,170,0.13); border-radius:5px;
  padding:15px 18px; overflow:hidden; background:linear-gradient(180deg,#132420,#0e1a17); }
.stat::before { content:""; position:absolute; left:0; top:0; bottom:0; width:2px; background:var(--c); }
.stat__val { font-family:var(--font-display); font-weight:900; font-size:2rem; line-height:1; color:var(--c); }
.stat__lbl { margin-top:8px; font-family:var(--font-mono); font-size:0.6rem; letter-spacing:0.2em;
  text-transform:uppercase; color:#8aa39c; }
.stat--total { --c:#e4f1ec; } .stat--issue { --c:#ff6a8a; }
.stat--skipped { --c:#6d8380; } .stat--ok { --c:#34e0a0; }

/* section headings */
.section { display:flex; align-items:center; gap:14px; margin:0 0 18px; }
.section__num { font-family:var(--font-mono); font-size:0.72rem; font-weight:700;
  letter-spacing:0.1em; color:var(--teal); }
.section__name { margin:0; font-family:var(--font-display); font-weight:700; font-size:1.05rem;
  letter-spacing:0.02em; text-transform:uppercase; color:var(--ink); }
.section__rule { flex:1; height:1px; background:linear-gradient(90deg, rgba(110,190,170,0.28), transparent); }
.section__count { font-family:var(--font-mono); font-size:0.7rem; color:#6d827c; }
.cards { display:flex; flex-direction:column; gap:14px; margin-bottom:42px; }
.cards__empty { display:none; margin:0; font-family:var(--font-mono); font-size:0.8rem; color:#6d827c; }

/* check cards */
.card { position:relative; overflow:hidden; border-radius:5px;
  background:linear-gradient(180deg,#132420,#0e1a17); border:1px solid rgba(110,190,170,0.13);
  box-shadow:0 10px 30px -22px rgba(0,0,0,0.9); }
.card--ok { --tone:#34e0a0; --tone-soft:rgba(52,224,160,0.11); --tone-bd:rgba(52,224,160,0.32); }
.card--issue { --tone:#ff6a8a; --tone-soft:rgba(255,106,138,0.12); --tone-bd:rgba(255,106,138,0.34);
  box-shadow:0 0 0 1px rgba(255,106,138,0.14), 0 16px 40px -26px rgba(255,90,120,0.5); }
.card--errored { --tone:#ffcf5c; --tone-soft:rgba(255,207,92,0.12); --tone-bd:rgba(255,207,92,0.32); }
.card--skipped { --tone:#6d8380; --tone-soft:rgba(109,131,128,0.10); --tone-bd:rgba(109,131,128,0.28); }
.card__bar { position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--tone);
  box-shadow:0 0 14px -1px var(--tone); }
.card__corner { position:absolute; width:9px; height:9px; }
.card__corner--tl { left:11px; top:9px; border-left:1px solid var(--tone-bd); border-top:1px solid var(--tone-bd); }
.card__corner--br { right:11px; bottom:9px; border-right:1px solid rgba(110,190,170,0.2);
  border-bottom:1px solid rgba(110,190,170,0.2); }
.card__pad { padding:19px 24px 19px 26px; }
.card__head { display:flex; align-items:center; gap:13px; flex-wrap:wrap; }
.card__num { font-family:var(--font-mono); font-size:11.5px; font-weight:700; letter-spacing:0.08em;
  color:var(--tone); background:var(--tone-soft); border:1px solid var(--tone-bd); border-radius:3px;
  padding:3px 8px; text-transform:uppercase; }
.card__title { margin:0; flex:1 1 auto; font-family:var(--font-display); font-weight:600;
  font-size:1.04rem; letter-spacing:-0.005em; color:var(--ink); }
.card__badge { display:inline-flex; align-items:center; gap:8px; font-family:var(--font-mono);
  font-size:0.68rem; font-weight:700; letter-spacing:0.16em; text-transform:uppercase; color:var(--tone);
  background:var(--tone-soft); border:1px solid var(--tone-bd); border-radius:3px; padding:5px 10px; }
.card__badge-dot { width:7px; height:7px; background:var(--tone); box-shadow:0 0 8px 0 var(--tone);
  transform:rotate(45deg); }
.card__details { margin:14px 0 0; font-family:var(--font-body); font-size:0.94rem; line-height:1.58;
  color:#c6ded4; text-wrap:pretty; }
.card__meta { margin-top:12px; display:inline-flex; align-items:center; gap:8px; font-family:var(--font-mono);
  font-size:0.7rem; letter-spacing:0.06em; color:#6d827c; }
.card__meta-arrow { color:var(--tone); }
.excerpt { margin-top:16px; border-radius:5px; overflow:hidden; border:1px solid rgba(110,190,170,0.16);
  background:#081311; }
.excerpt__head { display:flex; align-items:center; gap:9px; padding:8px 13px;
  border-bottom:1px solid rgba(110,190,170,0.13); background:rgba(110,190,170,0.05); }
.excerpt__dot { width:8px; height:8px; background:var(--tone); transform:rotate(45deg); flex:none; }
.excerpt__label { font-family:var(--font-mono); font-size:11px; font-weight:500; letter-spacing:0.05em; color:#a9c4bb; }
.excerpt__tag { margin-left:auto; font-family:var(--font-mono); font-size:9.5px; letter-spacing:0.22em;
  color:#5f746e; text-transform:uppercase; }
.excerpt__body { margin:0; padding:13px 16px; font-family:var(--font-mono); font-size:12.5px;
  line-height:1.65; color:#9fe4cf; overflow-x:auto; white-space:pre; }

/* footer */
.foot { margin-top:54px; padding-top:18px; border-top:1px solid rgba(110,190,170,0.14);
  display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; font-family:var(--font-mono);
  font-size:0.7rem; color:#5f746e; letter-spacing:0.04em; }

/* status filtering: hiding a status adds a body class */
body.hide-OK .card[data-status="OK"],
body.hide-SKIPPED .card[data-status="SKIPPED"],
body.hide-ISSUE .card[data-status="ISSUE"],
body.hide-ERRORED .card[data-status="ERRORED"] { display:none; }

/* motion */
@keyframes fac-grow { from { transform:scaleX(0); } to { transform:scaleX(1); } }
@keyframes fac-blink { 0%,100% { opacity:.35; } 50% { opacity:1; } }
button:focus-visible { outline:2px solid var(--teal); outline-offset:2px; }
@media (prefers-reduced-motion: reduce) { * { animation:none !important; } }

/* responsive */
@media (max-width:640px) {
  .cmdbar { padding:14px 18px; }
  .wrap { padding:26px 18px 70px; }
  .telem { grid-template-columns:repeat(2,1fr); }
  .cmdbar__meta { text-align:left; }
}
"""

# Inline script (end of <body>): status-filter toggles. Clicking a legend chip
# hides that status' cards (via a body class) and dims the chip; each section then
# shows a "no checks match" line when the active filter empties it.
_HTML_SCRIPT = """\
(function () {
  var body = document.body;
  function refresh() {
    var groups = document.querySelectorAll(".cards");
    for (var i = 0; i < groups.length; i++) {
      var cards = groups[i].querySelectorAll(".card");
      var visible = 0;
      for (var j = 0; j < cards.length; j++) {
        if (cards[j].offsetParent !== null) visible++;
      }
      var empty = groups[i].querySelector(".cards__empty");
      if (empty) empty.style.display = visible ? "none" : "block";
    }
  }
  var chips = document.querySelectorAll(".chip[data-filter]");
  for (var k = 0; k < chips.length; k++) {
    chips[k].addEventListener("click", function () {
      var hidden = body.classList.toggle("hide-" + this.getAttribute("data-filter"));
      this.classList.toggle("off", hidden);
      this.setAttribute("aria-pressed", (!hidden).toString());
      refresh();
    });
  }
  refresh();
})();
"""


def _verdict(counts: Counter) -> tuple[str, str, int]:
    """Derive (headline, tone-hex, count) for the HUD verdict badge from the counts.

    Mirrors the design component: issues dominate, then unrunnable checks, else a
    nominal all-clear. Only Sections 1-2 feed this (see ``render_report_html``)."""
    n_issue = counts.get(Status.ISSUE, 0)
    n_err = counts.get(Status.ERRORED, 0)
    if n_issue:
        headline = "One issue needs attention" if n_issue == 1 else f"{n_issue} issues need attention"
        return headline, "#ff6a8a", n_issue
    if n_err:
        headline = "One check could not run" if n_err == 1 else f"{n_err} checks could not run"
        return headline, "#ffcf5c", n_err
    return "All systems nominal", "#34e0a0", 0


def render_report_html(results: list[tuple[Check, CheckResult]], bundle_dir: str) -> str:
    """Render all results as one self-contained HTML page (the terminal "HUD" dossier)."""
    counts = Counter(res.status for _, res in results)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(counts.values())
    bar_total = total or 1  # avoid divide-by-zero for the proportional bar

    # Verdict reflects the deterministic Checks 1-11 / Info 1-5 only, so a broad
    # heuristic A1/A3 finding (section 3) never flips an otherwise-clean bundle to
    # "needs attention". The bar/legend/telemetry below still count all cards.
    verdict_counts = Counter(res.status for chk, res in results if chk.section in (1, 2))
    headline, vtone, vcount = _verdict(verdict_counts)
    sub = (f"{total} CHECKS RUN &middot; {counts.get(Status.OK, 0)} PASS &middot; "
           f"{counts.get(Status.ISSUE, 0)} FLAG &middot; {counts.get(Status.SKIPPED, 0)} SKIP")

    seg_order = (Status.ISSUE, Status.ERRORED, Status.OK, Status.SKIPPED)
    segments = "".join(
        f'<span class="seg seg--{_status_class(st)}" style="width:{counts[st] / bar_total * 100:.4f}%"></span>'
        for st in seg_order if counts.get(st, 0)
    )
    legend_order = (Status.OK, Status.ISSUE, Status.SKIPPED, Status.ERRORED)
    legend = "\n".join(
        f'    <button class="chip" type="button" data-filter="{st}" aria-pressed="true">'
        f'<span class="chip__swatch sw--{_status_class(st)}"></span>'
        f'<span class="chip__cnt">{counts.get(st, 0)}</span>'
        f'<span class="chip__lbl">{st.lower()}</span></button>'
        for st in legend_order
    )

    stats = (
        ("total", "checks run", total),
        ("issue", "issues", counts.get(Status.ISSUE, 0)),
        ("skipped", "skipped", counts.get(Status.SKIPPED, 0)),
        ("ok", "clean", counts.get(Status.OK, 0)),
    )
    telem = "\n".join(
        f'    <div class="stat stat--{key}"><div class="stat__val">{val}</div>'
        f'<div class="stat__lbl">{lbl}</div></div>'
        for key, lbl, val in stats
    )

    def section_html(num: int, idx: str, name: str) -> str:
        blocks = [_html_block(res) for chk, res in results if chk.section == num]
        cards = "\n".join(blocks)
        empty = '<p class="cards__empty">// no checks match the current filter</p>'
        body = f"{cards}\n{empty}" if cards else empty
        return (
            f'    <div class="section"><span class="section__num">{idx}</span>'
            f'<h2 class="section__name">{_esc(name)}</h2>'
            f'<span class="section__rule"></span>'
            f'<span class="section__count">{len(blocks)} checks</span></div>\n'
            f'    <div class="cards">\n{body}\n    </div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>faclog &middot; FortiAuthenticator log review</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chivo:wght@400;500;600;700;900&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
{_HTML_STYLE}</style>
</head>
<body>
<div class="page">
  <div class="page__glow"></div>

  <header class="cmdbar">
    <div class="cmdbar__brandwrap">
      <div class="hex hex--logo">
        <div class="hex__edge clip-hex"></div>
        <div class="hex__face clip-hex"></div>
        <div class="hex__core"><span class="hex__pip clip-hex"></span></div>
      </div>
      <div class="cmdbar__id">
        <span class="cmdbar__eyebrow">FortiAuthenticator &middot; Log Review</span>
        <span class="cmdbar__brand">faclog<span class="cmdbar__cursor">_</span></span>
      </div>
    </div>
    <div class="cmdbar__right">
      <div class="cmdbar__meta">
        <div class="cmdbar__meta-row">BUNDLE <span>{_esc(bundle_dir)}</span></div>
        <div class="cmdbar__meta-row">GENERATED <span>{_esc(generated)}</span></div>
      </div>
      <div class="cmdbar__status"><span class="cmdbar__status-dot"></span>scan complete</div>
    </div>
  </header>

  <div class="wrap">
    <section class="verdict" style="--vtone:{vtone}">
      <span class="vc vc--tl"></span><span class="vc vc--tr"></span><span class="vc vc--bl"></span><span class="vc vc--br"></span>
      <div class="verdict__head">
        <div class="hex hex--verdict">
          <div class="hex__edge clip-hex"></div>
          <div class="hex__face clip-hex"></div>
          <div class="hex__core"><span class="hex__count">{vcount}</span></div>
        </div>
        <div class="verdict__body">
          <div class="verdict__eyebrow">Diagnostic Verdict</div>
          <div class="verdict__headline">{_esc(headline)}</div>
          <div class="verdict__sub">{sub}</div>
        </div>
      </div>
      <div class="bar">{segments}</div>
      <div class="legend">
{legend}
      </div>
    </section>

    <div class="telem">
{telem}
    </div>

{section_html(1, "01", "Issues Found")}
{section_html(2, "02", "General Information")}
{section_html(3, "03", "Other Abnormalities")}

    <footer class="foot">
      <span>faclog &middot; FortiAuthenticator log analyzer</span>
      <span>{_esc(generated)}</span>
    </footer>
  </div>
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
