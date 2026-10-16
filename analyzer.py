#!/usr/bin/env python3
"""Analyze authentication logs (CSV or JSON) and flag repeated failed logins."""

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "status"}


def parse_timestamp(value):
    """Return a datetime for an ISO-like timestamp, or raise ValueError."""
    value = value.strip()
    if value[-1:] in {"Z", "z"}:
        value = value[:-1] + "+00:00"
    # Python 3.10 only accepts 3 or 6 fractional digits; pad/trim to 6.
    value = re.sub(
        r"\.(\d+)",
        lambda m: "." + m.group(1)[:6].ljust(6, "0"),
        value,
        count=1,
    )
    return datetime.fromisoformat(value)


def parse_row(row, line_number):
    """Validate one raw record (a dict) and return a normalized event dict."""
    if not isinstance(row, dict):
        raise ValueError("record must be an object with named fields")

    def field(name):
        value = row.get(name)
        return "" if value is None else str(value).strip()

    timestamp_text = field("timestamp")
    # Account names are compared case-insensitively.
    username = field("username").lower()
    source_ip = field("source_ip")
    status = field("status").upper()

    if not timestamp_text or not username or not source_ip:
        raise ValueError("timestamp, username and source_ip are required")
    if status not in {"SUCCESS", "FAILURE"}:
        raise ValueError("status must be SUCCESS or FAILURE")

    timestamp = parse_timestamp(timestamp_text)
    # Store the canonical form so equivalent addresses
    # (e.g. 2001:DB8::1 and 2001:db8:0:0:0:0:0:1) count together.
    source_ip = str(ipaddress.ip_address(source_ip))

    if timestamp.tzinfo is None:
        # Treat timestamps without a timezone as UTC so that
        # naive and aware values can be compared safely.
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return {
        "_dt": timestamp,
        "timestamp": timestamp.isoformat(),
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "line_number": line_number,
    }


def read_csv_rows(input_path):
    """Yield (line_number, row_dict) from a CSV file; validate the header."""
    with input_path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        # Normalize headers so " Username " matches "username".
        if reader.fieldnames:
            reader.fieldnames = [
                (name or "").strip().lower() for name in reader.fieldnames
            ]
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                "Missing required CSV columns: " + ", ".join(sorted(missing))
            )
        for line_number, row in enumerate(reader, start=2):
            yield line_number, row


def read_json_rows(input_path):
    """Yield (record_number, row_dict) from a JSON array or JSON Lines file."""
    text = input_path.read_text(encoding="utf-8-sig")
    stripped = text.strip()
    if not stripped:
        raise ValueError("JSON input file is empty")

    if stripped.startswith("["):
        try:
            records = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc
        numbered = enumerate(records, start=1)
    else:
        numbered = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                numbered.append((line_number, line))

    for number, record in numbered:
        if isinstance(record, str):
            try:
                record = json.loads(record)
            except json.JSONDecodeError as exc:
                yield number, ValueError(f"invalid JSON: {exc.msg}")
                continue
        if isinstance(record, dict):
            record = {str(k).strip().lower(): v for k, v in record.items()}
        yield number, record


def load_events(input_path):
    """Load and validate events from a CSV (.csv) or JSON (.json/.jsonl) file."""
    events = []
    errors = []

    suffix = input_path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        rows = read_json_rows(input_path)
    else:
        rows = read_csv_rows(input_path)

    for line_number, row in rows:
        try:
            if isinstance(row, ValueError):
                raise row
            events.append(parse_row(row, line_number))
        except (ValueError, TypeError) as exc:
            errors.append(f"Line {line_number}: {exc}")

    return events, errors


def max_failures_in_window(times, window):
    """Return the most failures that fall inside any span of `window`."""
    times = sorted(times)
    best = 0
    start = 0
    for end, moment in enumerate(times):
        while moment - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze_events(events, ip_threshold=5, user_threshold=5, window_minutes=None):
    """Return summary rows and failed events associated with flagged IPs/users.

    With window_minutes=None the thresholds apply to the whole file. Otherwise
    a key is flagged only if it reaches the threshold inside that time window.
    """
    failed = [event for event in events if event["status"] == "FAILURE"]

    ip_counts = Counter(event["source_ip"] for event in failed)
    user_counts = Counter(event["username"] for event in failed)

    if window_minutes is None:
        ip_scores = ip_counts
        user_scores = user_counts
    else:
        window = timedelta(minutes=window_minutes)
        ip_times, user_times = {}, {}
        for event in failed:
            ip_times.setdefault(event["source_ip"], []).append(event["_dt"])
            user_times.setdefault(event["username"], []).append(event["_dt"])
        ip_scores = {k: max_failures_in_window(v, window) for k, v in ip_times.items()}
        user_scores = {k: max_failures_in_window(v, window) for k, v in user_times.items()}

    flagged_ips = {
        source_ip for source_ip, score in ip_scores.items()
        if score >= ip_threshold
    }
    flagged_users = {
        username for username, score in user_scores.items()
        if score >= user_threshold
    }

    ip_rows = [
        {
            "source_ip": source_ip,
            "failed_logins": count,
            "flagged": "YES" if source_ip in flagged_ips else "NO",
        }
        for source_ip, count in ip_counts.most_common()
    ]
    user_rows = [
        {
            "username": username,
            "failed_logins": count,
            "flagged": "YES" if username in flagged_users else "NO",
        }
        for username, count in user_counts.most_common()
    ]
    flagged_events = [
        event for event in failed
        if event["source_ip"] in flagged_ips or event["username"] in flagged_users
    ]

    return ip_rows, user_rows, flagged_events, flagged_ips, flagged_users


CHART_BUCKET_MINUTES = [1, 5, 10, 15, 30, 60, 180, 360, 720, 1440]


def bucket_failures(events, flagged_ips, flagged_users, max_buckets=40):
    """Group failed events into time buckets; return (bucket_minutes, rows).

    Each row is (bucket_start, flagged_count, other_count).
    """
    failed = [e for e in events if e["status"] == "FAILURE"]
    if not failed:
        return 1, []

    first = min(e["_dt"] for e in failed)
    last = max(e["_dt"] for e in failed)
    span_minutes = (last - first).total_seconds() / 60

    size = CHART_BUCKET_MINUTES[-1]
    for candidate in CHART_BUCKET_MINUTES:
        if span_minutes / candidate < max_buckets:
            size = candidate
            break

    step = timedelta(minutes=size)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    origin = epoch + ((first - epoch) // step) * step

    count = int((last - origin) // step) + 1
    flagged_counts = [0] * count
    other_counts = [0] * count
    for event in failed:
        index = int((event["_dt"] - origin) // step)
        if event["source_ip"] in flagged_ips or event["username"] in flagged_users:
            flagged_counts[index] += 1
        else:
            other_counts[index] += 1

    rows = [
        (origin + i * step, flagged_counts[i], other_counts[i])
        for i in range(count)
    ]
    return size, rows


def build_chart_svg(events, flagged_ips, flagged_users):
    """Return an SVG string: failed logins over time, flagged vs other."""
    size, rows = bucket_failures(events, flagged_ips, flagged_users)
    width, height = 800, 420
    left, right, top, bottom = 60, 20, 60, 70
    plot_w, plot_h = width - left - right, height - top - bottom

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{left}" y="28" font-size="16" font-weight="bold">'
        "Failed logins over time</text>",
    ]

    if not rows:
        parts.append(
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" '
            'fill="#555555">No failed logins found</text>'
        )
        parts.append("</svg>")
        return "\n".join(parts)

    parts.append(
        f'<text x="{left}" y="46" fill="#555555">'
        f"Bucket size: {size} minute(s), times in UTC</text>"
    )

    max_total = max(f + o for _, f, o in rows)
    y_max = max(max_total, 1)

    # Y axis gridlines and labels (integers only).
    ticks = min(y_max, 5)
    for i in range(ticks + 1):
        value = round(y_max * i / ticks)
        y = top + plot_h - (plot_h * value / y_max)
        parts.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" '
            'stroke="#dddddd"/>'
        )
        parts.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{value}</text>'
        )

    slot = plot_w / len(rows)
    bar_w = max(slot * 0.8, 1)
    label_every = max(1, len(rows) // 10)
    for i, (start, flagged_n, other_n) in enumerate(rows):
        x = left + i * slot + (slot - bar_w) / 2
        other_h = plot_h * other_n / y_max
        flagged_h = plot_h * flagged_n / y_max
        base = top + plot_h
        if other_n:
            parts.append(
                f'<rect x="{x:.1f}" y="{base - other_h:.1f}" width="{bar_w:.1f}" '
                f'height="{other_h:.1f}" fill="#9aa5b1"/>'
            )
        if flagged_n:
            parts.append(
                f'<rect x="{x:.1f}" y="{base - other_h - flagged_h:.1f}" '
                f'width="{bar_w:.1f}" height="{flagged_h:.1f}" fill="#d64545"/>'
            )
        if i % label_every == 0:
            label = start.strftime("%m-%d %H:%M")
            lx = x + bar_w / 2
            parts.append(
                f'<text x="{lx:.1f}" y="{base + 16}" text-anchor="end" '
                f'transform="rotate(-40 {lx:.1f} {base + 16})">{escape(label)}</text>'
            )

    base = top + plot_h
    parts.append(
        f'<line x1="{left}" y1="{base}" x2="{width - right}" y2="{base}" stroke="#333333"/>'
    )
    parts.append(
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{base}" stroke="#333333"/>'
    )
    # Legend.
    lx = width - right - 230
    parts.append(f'<rect x="{lx}" y="14" width="12" height="12" fill="#d64545"/>')
    parts.append(f'<text x="{lx + 18}" y="25">Flagged IP/user</text>')
    parts.append(f'<rect x="{lx + 120}" y="14" width="12" height="12" fill="#9aa5b1"/>')
    parts.append(f'<text x="{lx + 138}" y="25">Other failures</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def write_csv(path, rows, fieldnames):
    """Write dictionaries to CSV with a stable header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run(input_path, output_dir, ip_threshold=5, user_threshold=5,
        window_minutes=None, chart=False):
    if ip_threshold < 1 or user_threshold < 1:
        raise ValueError("Thresholds must be at least 1.")
    if window_minutes is not None and window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    events, errors = load_events(input_path)
    ip_rows, user_rows, flagged_events, flagged_ips, flagged_users = analyze_events(
        events, ip_threshold, user_threshold, window_minutes
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_dir / "ip_summary.csv",
        ip_rows,
        ["source_ip", "failed_logins", "flagged"],
    )
    write_csv(
        output_dir / "user_summary.csv",
        user_rows,
        ["username", "failed_logins", "flagged"],
    )
    write_csv(
        output_dir / "flagged_events.csv",
        flagged_events,
        ["timestamp", "username", "source_ip", "status", "line_number"],
    )

    chart_path = None
    if chart:
        chart_path = output_dir / "failures_over_time.svg"
        chart_path.write_text(
            build_chart_svg(events, flagged_ips, flagged_users), encoding="utf-8"
        )

    print("\n=== Failed Login Analyzer ===")
    print(f"Valid events analyzed : {len(events)}")
    print(f"Failed login events   : {sum(1 for e in events if e['status'] == 'FAILURE')}")
    print(f"Successful logins     : {sum(1 for e in events if e['status'] == 'SUCCESS')}")
    if window_minutes is not None:
        print(f"Time window           : {window_minutes} minute(s)")
    print(f"Flagged source IPs    : {len(flagged_ips)}")
    print(f"Flagged usernames     : {len(flagged_users)}")
    print(f"Reports saved to      : {output_dir.resolve()}")
    if chart_path:
        print(f"Chart saved to        : {chart_path.resolve()}")

    if flagged_ips:
        print("\nSource IPs to review:")
        for row in ip_rows:
            if row["flagged"] == "YES":
                print(f"  {row['source_ip']}: {row['failed_logins']} failed logins")

    if flagged_users:
        print("\nAccounts to review:")
        for row in user_rows:
            if row["flagged"] == "YES":
                print(f"  {row['username']}: {row['failed_logins']} failed logins")

    if errors:
        print(f"\nSkipped rows with errors: {len(errors)}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)

    print("\nReminder: a threshold match is an investigation lead, not proof of an attack.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication CSV logs for repeated failed logins."
    )
    parser.add_argument("--input", type=Path, default=Path("sample_logs.csv"),
                        help="Path to the input .csv, .json or .jsonl file (default: sample_logs.csv)")
    parser.add_argument("--out", type=Path, default=Path("reports"),
                        help="Output directory (default: reports)")
    parser.add_argument("--ip-threshold", type=int, default=5,
                        help="Flag source IPs with at least this many failures (default: 5)")
    parser.add_argument("--user-threshold", type=int, default=5,
                        help="Flag usernames with at least this many failures (default: 5)")
    parser.add_argument("--window-minutes", type=int, default=None,
                        help="Only count failures inside this many minutes "
                             "(default: count across the whole file)")
    parser.add_argument("--chart", action="store_true",
                        help="Also write failures_over_time.svg to the output directory")
    args = parser.parse_args()

    try:
        return run(args.input, args.out, args.ip_threshold, args.user_threshold,
                   args.window_minutes, args.chart)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
