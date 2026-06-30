# faclog — FortiAuthenticator Log Analyzer

A static **health-check linter** for FortiAuthenticator diagnostic bundles. Point it at a
directory of component logs and it reports *latent / general* issues — conditions that have
caused problems across deployments — rather than diagnosing one specific fault.

It is a single, self-contained Python 3 script with **no dependencies** (standard library
only), so it runs on an air-gapped support box. The only network use is Check 6, and it stays
off unless you explicitly ask for it.

## Requirements

- Python 3.9+
- No third-party packages.

## Usage

```
python3 faclog.py [bundle_dir] [-o OUTPUT] [--check-network]
```

| Argument / flag | Meaning |
|---|---|
| `bundle_dir` | Directory holding the diagnostic bundle. Optional; defaults to the current directory (`.`). |
| `-o`, `--output PATH` | Write the report to `PATH` instead of stdout. |
| `--check-network` | Enable the Check 6 live reachability probe (default **off**). |
| `-h`, `--help` | Show usage and exit. |

### Examples

```bash
# Analyze a bundle, print the report to the terminal
python3 faclog.py /path/to/bundle

# Write the report to a file
python3 faclog.py /path/to/bundle -o report.txt

# Also run the live reachability probe (Check 6)
python3 faclog.py /path/to/bundle --check-network
```

## Input: the bundle directory

The directory holds an **arbitrary subset** of the files below — any file may be absent, and a
missing file is normal (its checks report `SKIPPED`, not an error). Rotated logs with numeric
suffixes (`access_log`, `access_log.1`, …) are picked up automatically.

| File(s) | Source |
|---|---|
| `gui-db.log`, `fac.logs` | Forti event log (`key=value`); `fac.logs` is a superset of `gui-db.log`. |
| `access_log`, `access_log.1`, … | Apache access log. |
| `error_log` | Apache error log. |
| `fgdfac.log` | Forti daemon (ISO8601 lines + multi-line HTTP dumps). |
| `kern.log*`, `syslog*` | Kernel/dmesg + syslog. |
| `wad.log` | `wad` proxy daemon. |
| `disk_usage` | Output of `df -h`. |
| `curproc` | Combined `ps` + `top` output. |
| `meminfo` | Contents of `/proc/meminfo`. |
| `fwinfo` | Firmware / model / HA / license summary. |

## Output

A plain-text report with two banner sections:

- **SECTION 1 — ISSUES FOUND**: Checks `1, 2a, 2b, 3, 4a, 4b, 5, 6, 7, 8, 9, 10, 11`.
- **SECTION 2 — GENERAL INFORMATION**: `Info 1`–`Info 5`.

Every check always emits one of four results, and the numbering is fixed (it never drifts when
checks are skipped):

| Result | Meaning |
|---|---|
| `OK` | The check ran and found nothing. |
| `SKIPPED` | The source file(s) were absent. |
| `ISSUE` | Something to report, with details, timestamp, and a log excerpt. |
| `ERRORED` | An unexpected failure inside the check (isolated so the run continues). |

### What it checks

**Section 1 — issues**

1. Incorrect configuration (chap/mschap triple auth)
2. Brute force — `2a` via auth logs, `2b` via web logs
3. Unintended reboot
4. Clock health — `4a` NTP instability, `4b` system clock drift vs HTTP server time
5. Remote LDAP reachability (per-IP outage summary over the last 30 days)
6. Webserver URL reachability — *network-gated*; reachable is treated as **bad**
7. Out-of-Memory events
8. Process crashes (segfault)
9. Bad HTTP responses in `wad.log`
10. Disk usage on `/var` and `/data`
11. EXT4 filesystem errors

**Section 2 — general information**

- Info 1: CPU cores · Info 2: Memory · Info 3: Resource-spec compliance ·
  Info 4: HA operation · Info 5: Top recurring log lines

## Notes

- **Check 6 (`--check-network`)** is the only check that touches the network. With the flag
  off, it lists the candidate URL(s) and marks the result `not-tested`. With it on, it probes
  each (short timeout, stdlib only) and flags any that are reachable.
- The **"last 30 days"** window (Checks 5 and Info 5) is measured relative to the most recent
  timestamp found in the source, since a static bundle has no reliable "now".
- Timestamps without a timezone are assumed to be **UTC**.
