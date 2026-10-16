# Python Failed Login Analyzer

A small, dependency-free command-line tool that reads authentication logs, counts failed logins by source IP and username, flags repeated failures, and exports CSV reports and an optional chart.

It is a beginner-friendly **defensive security** project: it shows how simple log analysis can surface brute-force or password-guessing patterns for a human to investigate.

> **Note:** Repeated login failures are an investigation lead, not proof of an attack. Always review the surrounding context before making a security decision.

## Features

- Reads logs from **CSV**, **JSON** (array), or **JSON Lines** files
- Counts failed logins per **source IP** and per **username**
- Flags IPs and accounts that reach configurable **thresholds**
- Optional **sliding time window** (for example, 5 failures within 10 minutes)
- Exports three CSV reports and an optional **SVG chart** of failures over time
- Validates every row and reports bad ones without stopping the run
- Normalizes data so equivalent values count together (IP formats, username case, header spacing)
- Uses only the Python standard library, with a unit test suite included

## Requirements

- Python 3.10 or newer
- No third-party packages

## Quick start

```bash
git clone https://github.com/<your-username>/python-failed-login-analyzer.git
cd python-failed-login-analyzer
python analyzer.py
```

On some systems use `python3` instead of `python`. With no arguments the tool analyzes `sample_logs.csv` and writes reports to a `reports/` folder.

## Usage

```bash
python analyzer.py --input sample_logs.csv --out reports
```

| Option | Default | Description |
|---|---|---|
| `--input` | `sample_logs.csv` | Input file (`.csv`, `.json`, or `.jsonl`) |
| `--out` | `reports` | Output directory (created if missing) |
| `--ip-threshold` | `5` | Flag source IPs with at least this many failures |
| `--user-threshold` | `5` | Flag usernames with at least this many failures |
| `--window-minutes` | off | Only count failures that occur within this many minutes |
| `--chart` | off | Also write `failures_over_time.svg` |

### Examples

```bash
# Different thresholds for IPs and users
python analyzer.py --ip-threshold 5 --user-threshold 4

# Flag only bursts: 5 failures within 10 minutes
python analyzer.py --window-minutes 10

# Read JSON or JSON Lines
python analyzer.py --input sample_logs.json
python analyzer.py --input sample_logs.jsonl

# Generate the chart
python analyzer.py --chart
```

Without `--window-minutes`, failures are counted across the whole file. The file format is chosen from the file extension.

## Sample output

```text
=== Failed Login Analyzer ===
Valid events analyzed : 17
Failed login events   : 13
Successful logins     : 4
Time window           : 10 minute(s)
Flagged source IPs    : 2
Flagged usernames     : 2
Reports saved to      : /path/to/reports
Chart saved to        : /path/to/reports/failures_over_time.svg

Source IPs to review:
  192.0.2.10: 5 failed logins
  198.51.100.8: 5 failed logins

Accounts to review:
  amit: 5 failed logins
  admin: 5 failed logins

Reminder: a threshold match is an investigation lead, not proof of an attack.
```

## Output files

| File | Contents |
|---|---|
| `ip_summary.csv` | Failed login counts per source IP, with a `flagged` column |
| `user_summary.csv` | Failed login counts per username, with a `flagged` column |
| `flagged_events.csv` | The failed events tied to flagged IPs or usernames |
| `failures_over_time.svg` | Only with `--chart`. Stacked bars of failures per time bucket (red = flagged, gray = other). Open it in any web browser. |

## Input format

Every record needs four fields:

| Field | Description |
|---|---|
| `timestamp` | ISO-style timestamp, e.g. `2026-10-15T09:01:00` or `2026-10-15T09:01:00Z` |
| `username` | Account name |
| `source_ip` | IPv4 or IPv6 address |
| `status` | `SUCCESS` or `FAILURE` (case-insensitive) |

**CSV**

```csv
timestamp,username,source_ip,status
2026-10-15T09:01:00,amit,192.0.2.10,FAILURE
2026-10-15T09:02:00,amit,192.0.2.10,SUCCESS
```

**JSON** (`.json`, an array of objects)

```json
[
  {"timestamp": "2026-10-15T09:01:00", "username": "amit", "source_ip": "192.0.2.10", "status": "FAILURE"}
]
```

**JSON Lines** (`.jsonl`, one object per line)

```json
{"timestamp": "2026-10-15T09:01:00", "username": "amit", "source_ip": "192.0.2.10", "status": "FAILURE"}
```

The sample files use documentation-only IP addresses (TEST-NET ranges) and contain no real user activity.

## How it works

1. Read each record and validate the fields. Invalid rows are skipped and listed on stderr.
2. Normalize values: headers and status are case-insensitive, usernames are lowercased, IP addresses are converted to a canonical form, and timestamps without a timezone are treated as UTC.
3. Count `FAILURE` events by IP and by username.
4. Flag a key when its count reaches the threshold. With `--window-minutes`, the count is the most failures inside any window of that length (a sliding window; the window edge is inclusive).
5. Write the summaries, the related failed events, and the optional chart.

## Project structure

```text
python-failed-login-analyzer/
├── analyzer.py
├── sample_logs.csv
├── sample_logs.json
├── sample_logs.jsonl
├── tests/
│   └── test_analyzer.py
├── reports/              # created when you run the program
└── README.md
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Limitations

- Detection is rule-based (counts and time windows). There is no geolocation, threat intelligence, or machine learning.
- It reads files in one pass and is meant for small to medium log files, not live monitoring.
- It never blocks accounts or IPs. Use its output as a starting point for manual review.

## Ideas for improvement

- Support more log formats (syslog, Windows event logs)
- Add a short incident-report template for flagged results
- Add a summary of successful logins that follow a burst of failures

## Safe use

Use this tool only on logs you own or are authorized to analyze. Do not commit real credentials, sensitive logs, or personal data to a public repository. Never block accounts or IPs automatically based only on a simple threshold rule.
