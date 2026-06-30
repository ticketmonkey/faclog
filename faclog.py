#!/usr/bin/env python3
"""FortiAuthenticator Log Analyzer.

A static health-check linter for FortiAuthenticator diagnostic bundles. It reads a
directory of heterogeneous component logs (Apache, kernel, RADIUS/LDAP, the ``wad``
proxy, NTP, custom Forti daemons) and reports *latent / general* issues -- conditions
that have caused problems across deployments -- rather than diagnosing one reported
fault.

This file is the framework (spec Sections 0-4):

    (0) Named thresholds          -- all tunables in one place.
    (1) Timestamp normalization   -- every component log into tz-aware UTC.
    (2) BundleReader              -- rotation-aware, missing-file-tolerant file access.
    (3) Check contract + runner   -- OK / SKIPPED / ISSUE / ERRORED, per-check isolation.
    (4) Reporter + CLI            -- two banner sections, fixed check numbering.

The individual detection checks (spec Sections 5-6) are registered here as stubs so the
framework runs end-to-end; their real logic lands in later work.

Standard library only -- the bundle may be analyzed on an air-gapped support box. The
sole network use is Check 6, gated behind ``--check-network`` (default off), and it too
uses stdlib only.
"""

from __future__ import annotations

import argparse
import email.utils
import glob
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
# (5/6) Registered checks -- STUBS.
#
# Each check is a real registry entry with a docstring linking to the signature it will
# detect, but the body currently only reports SKIPPED (source absent) or a placeholder
# OK. Real detection logic lands in later deliverables. Numbering is authoritative here.
# ---------------------------------------------------------------------------

_FORTI_EVENT = ("gui-db.log", "fac.logs")


def _stub(ctx: Context, number: str, title: str, *files: str) -> CheckResult:
    """Shared stub body: SKIPPED if no source file present, else placeholder OK."""
    if files and not ctx.reader.present(*files):
        return skipped(number, title)
    return ok(number, title, details="not yet implemented")


@register("1", "Incorrect configuration (chap/mschap triple auth)")
def check_1(ctx: Context) -> CheckResult:
    """Detect one user failing chap + mschap + 'authentication  ' (double-space) auth
    three times at ~1s intervals -- the misconfigured-token signature."""
    return _stub(ctx, "1", "Incorrect configuration (chap/mschap triple auth)", *_FORTI_EVENT)


@register("2a", "Brute force via auth logs")
def check_2a(ctx: Context) -> CheckResult:
    """Flag many 'invalid user' failures within AUTH_WINDOW_SECONDS."""
    return _stub(ctx, "2a", "Brute force via auth logs", *_FORTI_EVENT)


@register("2b", "Brute force via web logs")
def check_2b(ctx: Context) -> CheckResult:
    """Flag source IPs exceeding WEB_PER_MINUTE_THRESHOLD requests per minute in access_log."""
    return _stub(ctx, "2b", "Brute force via web logs", "access_log")


@register("3", "Unintended reboot")
def check_3(ctx: Context) -> CheckResult:
    """Detect 'recovered from an unintended/unusual shutdown/reboot' power-cycle messages."""
    return _stub(ctx, "3", "Unintended reboot", *_FORTI_EVENT)


@register("4a", "NTP instability")
def check_4a(ctx: Context) -> CheckResult:
    """Detect NTPD time adjustments that oscillate forward then back."""
    return _stub(ctx, "4a", "NTP instability", *_FORTI_EVENT)


@register("4b", "System clock drift vs HTTP server time")
def check_4b(ctx: Context) -> CheckResult:
    """Compare local log time against the HTTP Date: header; flag deltas > CLOCK_DRIFT_SECONDS."""
    return _stub(ctx, "4b", "System clock drift vs HTTP server time", "fgdfac.log")


@register("5", "Remote LDAP reachability")
def check_5(ctx: Context) -> CheckResult:
    """Pair LDAP unreachable->available transitions per IP; summarize over LOOKBACK_DAYS."""
    return _stub(ctx, "5", "Remote LDAP reachability", *_FORTI_EVENT)


@register("6", "Webserver URL reachability")
def check_6(ctx: Context) -> CheckResult:
    """Extract FQDN:port from error_log; reachability is inverted (reachable = bad).
    Network probe gated behind --check-network (default off)."""
    title = "Webserver URL reachability"
    if not ctx.reader.present("error_log"):
        return skipped("6", title)
    if not ctx.check_network:
        return ok("6", title, details="network probing off (--check-network); not-tested")
    return ok("6", title, details="not yet implemented")


@register("7", "Out-of-Memory events")
def check_7(ctx: Context) -> CheckResult:
    """Find 'oom-kill' / 'Out of memory: Killed process' in kernel/syslog."""
    return _stub(ctx, "7", "Out-of-Memory events", "kern.log", "syslog")


@register("8", "Process crashes (segfault)")
def check_8(ctx: Context) -> CheckResult:
    """Find 'segfault' lines grouped by crashing process name."""
    return _stub(ctx, "8", "Process crashes (segfault)", "kern.log", "syslog")


@register("9", "Bad HTTP responses in wad.log")
def check_9(ctx: Context) -> CheckResult:
    """Find 'Http response is not OK ... http_code=' grouped by http_code."""
    return _stub(ctx, "9", "Bad HTTP responses in wad.log", "wad.log")


@register("10", "Disk usage")
def check_10(ctx: Context) -> CheckResult:
    """Flag usage > DISK_USAGE_PCT_THRESHOLD on watched mountpoints only."""
    return _stub(ctx, "10", "Disk usage", "disk_usage")


@register("11", "EXT4 filesystem errors")
def check_11(ctx: Context) -> CheckResult:
    """Find multi-line 'EXT4-fs (<dev>): error' blocks grouped by device."""
    return _stub(ctx, "11", "EXT4 filesystem errors", "kern.log", "syslog")


@register("Info 1", "CPU cores", section=2)
def info_1(ctx: Context) -> CheckResult:
    """Core count = max CPU id + 1, read from the top block in curproc."""
    return _stub(ctx, "Info 1", "CPU cores", "curproc")


@register("Info 2", "Memory", section=2)
def info_2(ctx: Context) -> CheckResult:
    """Report total / free / available RAM in GB from meminfo."""
    return _stub(ctx, "Info 2", "Memory", "meminfo")


@register("Info 3", "Resource-spec compliance", section=2)
def info_3(ctx: Context) -> CheckResult:
    """Select sizing table by FW version (boundary FW_TABLE_BOUNDARY) and compare
    required vs actual CPU/RAM/Disk for licensed Max users."""
    return _stub(ctx, "Info 3", "Resource-spec compliance", "fwinfo")


@register("Info 4", "HA operation", section=2)
def info_4(ctx: Context) -> CheckResult:
    """Print the HA info block; flag status/role errors."""
    return _stub(ctx, "Info 4", "HA operation", "fwinfo")


@register("Info 5", "Top recurring log lines", section=2)
def info_5(ctx: Context) -> CheckResult:
    """Show the 10 most frequent log lines over LOOKBACK_DAYS, after normalizing out
    timestamps/IPs/FQDNs."""
    return _stub(ctx, "Info 5", "Top recurring log lines", "fac.logs")


# ---------------------------------------------------------------------------
# (4) Reporter.
# ---------------------------------------------------------------------------

_RULE = "-" * 78
_BANNER = "=" * 78


def _render_block(r: CheckResult) -> list[str]:
    lines = [_RULE, f"Check {r.number} - {r.title}", f"  Result    : {r.status}"]
    if r.details:
        lines.append(f"  Details   : {r.details}")
    if r.status == Status.ISSUE:
        lines.append(f"  Timestamp : {to_display(r.timestamp)}")
        excerpt = r.excerpt if r.excerpt else "(none)"
        lines.append("  Log excerpt:")
        for ln in excerpt.splitlines() or [""]:
            lines.append(f"    {ln}")
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
# Orchestration + CLI.
# ---------------------------------------------------------------------------


def analyze(bundle_dir: str, check_network: bool = False) -> str:
    """Run every registered check against ``bundle_dir`` and render the report."""
    ctx = Context(reader=BundleReader(bundle_dir), check_network=check_network)
    results = [(chk, run_check(chk, ctx)) for chk in REGISTRY]
    return render_report(results)


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
        "-o", "--output", default=None,
        help="Write the report to this path (default: stdout).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isdir(args.bundle_dir):
        sys.stderr.write(f"error: not a directory: {args.bundle_dir}\n")
        return 2
    report = analyze(args.bundle_dir, check_network=args.check_network)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        sys.stdout.write(report + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
