# FortiAuthenticator Log Analyzer — Project Guide

## Mission

`faclog.py` is a **static health-check linter** for FortiAuthenticator diagnostic bundles.
It does *not* diagnose one reported fault — it scans a support bundle for **latent / general
issues** that have caused problems across deployments and may cause future ones. Think
"linter for a support bundle," not "incident debugger."

A FortiAuthenticator wraps many independent components (Apache, the Linux kernel,
RADIUS/LDAP, a `wad` proxy, NTP, custom Forti daemons). Each writes its own log in its own
format, so the tool must tolerate **heterogeneous timestamps, hostnames, and timezones** —
across files and even within a single check.

## Hard rules (do not break these)

- **Single self-contained script, stdlib only.** Everything lives in `faclog.py`. The bundle
  may be analyzed on an air-gapped box. The *only* network use is Check 6, gated behind
  `--check-network` (default **off**), and it too is stdlib-only.
- **Every check always emits a result** — one of four states: `OK` (ran, found nothing),
  `SKIPPED` (source file absent — this is normal, not an error), `ISSUE` (with details), or
  `ERRORED` (unexpected failure, isolated). Never silently omit a check.
- **Per-check isolation.** A malformed line or missing file in one check must never abort the
  run. `run_check()` wraps each check in try/except → `ERRORED`.
- **Fixed numbering.** Render order is exactly `1, 2a, 2b, 3, 4a, 4b, 5, 6, 7, 8, 9, 10, 11`
  then `Info 1–5`. Numbering must not drift when checks are skipped — it is fixed in the
  `REGISTRY`, not derived at runtime. (This spec's numbering overrides any sample report.)
- **All thresholds are named constants** in the constants block near the top of `faclog.py`
  (auth window, brute-force counts, disk %, clock drift, lookback days). No magic numbers
  buried in checks.
- **Timestamps normalize through one layer.** `parse_timestamp()` → tz-aware UTC. Missing
  offset/timezone → **assumed UTC** (`ASSUMED_TZ`, documented in one place). Unparseable →
  `None` → rendered `(unknown time)`. This layer never raises.
- **Multi-line events are real.** HTTP dumps in `fgdfac.log`, `segfault`+`Code:`, EXT4 error
  blocks span multiple lines — don't assume one line per event.
- **De-duplicate & summarize.** When an issue recurs, report total count + only the latest
  excerpt(s) by timestamp (`Occurrences` helper).

## Input contract

- Positional CLI arg is a **directory** (default `.`) holding an **arbitrary subset** of the
  bundle files. Any file may be absent — that's normal.
- Files rotate with numeric suffixes (`access_log`, `access_log.1`, …); `BundleReader.find()`
  globs rotations and orders them oldest→newest. Use it, don't open files directly.

File inventory: `gui-db.log`/`fac.logs` (Forti key=value events), `access_log*` (Apache
access), `error_log` (Apache error), `fgdfac.log` (Forti daemon, ISO8601 + HTTP dumps),
`kern.log*`/`syslog*` (kernel/dmesg), `wad.log` (proxy), `disk_usage` (`df -h`), `curproc`
(`ps`+`top`), `meminfo` (`/proc/meminfo`), `fwinfo` (firmware/model/HA/license).

## Code layout (`faclog.py`)

1. **Constants** — all tunables.
2. **Timestamp normalization** — `parse_timestamp`, `to_display`.
3. **`BundleReader`** — rotation-aware, missing-file-tolerant file access.
4. **Check contract** — `CheckResult`, `Status`, `Check`, `Context`, `REGISTRY`,
   `register()`, `run_check()`, `Occurrences`.
5. **Checks (Sections 5–6)** — one `@register`ed function per check/info, with detection
   logic implemented. Shared parsing helpers (`_forti_fields`, `_forti_lines`,
   `_kernel_lines`, `_cpu_core_count`, `_memory_gb`) sit alongside the checks; Info-3
   sizing tables are encoded as data (`RESOURCE_TABLE_A`/`_B`).
6. **Reporter** — `render_report()` emits the two banner sections.
7. **CLI** — `argparse`: positional `bundle_dir`, `--check-network`, `-o/--output`.

## Status

Built end-to-end: framework (spec Sections 0–4) plus detection logic for all of Checks 1–11
and Info 1–5 (spec Sections 5–6), reusing the normalization layer, `BundleReader`, and
`Occurrences`. Two assumptions to note: the "last 30 days" window (Checks 5, Info 5) is
relative to the most recent timestamp in the source (no reliable "now" on an air-gapped box),
and Check 6 network probing stays off unless `--check-network` is passed.

## Run

```
python3 faclog.py /path/to/bundle           # report to stdout
python3 faclog.py /path/to/bundle -o report.txt
python3 faclog.py /path/to/bundle --check-network   # enable Check 6 live probe
```
