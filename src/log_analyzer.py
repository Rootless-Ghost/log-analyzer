#!/usr/bin/env python3
"""
Log Analyzer - Security Log Analysis Tool
Author: RootlessGhost
Description: Parses security logs, detects suspicious activity, and generates reports.
"""

import argparse
import sys
import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Detect suspicious activity in log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py --input logs/security.csv --type windows
  python log_analyzer.py --input /var/log/auth.log --type linux --report html
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the log file to analyze"
    )
    
    parser.add_argument(
        "-t", "--type",
        choices=["windows", "linux"],
        default="windows",
        help="Type of log file (default: windows)"
    )
    
    parser.add_argument(
        "-r", "--report",
        choices=["terminal", "html", "csv"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./output",
        help="Output directory for reports (default: ./output)"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def print_banner():
    """Print the tool banner."""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║           LOG ANALYZER v1.0               ║
    ║       Security Log Analysis Tool          ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)


def validate_input_file(filepath: str) -> Path:
    """Validate that the input file exists and is readable."""
    path = Path(filepath)
    
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    
    if not path.is_file():
        print(f"[ERROR] Not a file: {filepath}")
        sys.exit(1)
    
    return path


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    # TODO: Implement YAML config loading
    # For now, return default config
    return {
        "brute_force_threshold": 5,
        "brute_force_window": 5,
        "off_hours_start": 0,
        "off_hours_end": 5
    }


def parse_windows_log(filepath: Path) -> list:
    """
    Parse Windows Security Event Log (CSV format).
    
    Expected CSV columns:
    - TimeCreated
    - EventID
    - SourceIP (or IpAddress)
    - TargetUserName
    - LogonType
    - Status
    """
    print(f"[*] Parsing Windows log: {filepath}")
    events = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                event = {
                    'timestamp': datetime.strptime(row['TimeCreated'], '%Y-%m-%d %H:%M:%S'),
                    'event_id': int(row['EventID']),
                    'source_ip': row.get('SourceIP', row.get('IpAddress', 'Unknown')),
                    'username': row.get('TargetUserName', 'Unknown'),
                    'logon_type': row.get('LogonType', ''),
                    'status': row.get('Status', 'Unknown')
                }
                events.append(event)
        
        print(f"[+] Parsed {len(events)} events")
        
    except Exception as e:
        print(f"[ERROR] Failed to parse log file: {e}")
        sys.exit(1)
    
    return events


def parse_linux_log(filepath: Path) -> list:
    """
    Parse Linux auth.log file.
    
    Extracts:
    - Timestamp
    - Service (sshd, sudo, etc.)
    - Action (Accepted, Failed, etc.)
    - Username
    - Source IP
    """
    # TODO: Implement Linux log parsing
    print(f"[*] Parsing Linux log: {filepath}")
    events = []
    return events


def detect_brute_force(events: list, threshold: int = 5, window_minutes: int = 5) -> list:
    """
    Detect brute force attempts.
    
    Flags when there are X or more failed login attempts
    from the same source within Y minutes.
    """
    alerts = []
    
    # Filter for failed logins (Event ID 4625)
    failed_logins = [e for e in events if e['event_id'] == 4625]
    
    # Group by source IP
    by_source = defaultdict(list)
    for event in failed_logins:
        by_source[event['source_ip']].append(event)
    
    # Check each source for brute force pattern
    for source_ip, source_events in by_source.items():
        # Sort by timestamp
        source_events.sort(key=lambda x: x['timestamp'])
        
        # Sliding window check
        for i, event in enumerate(source_events):
            window_start = event['timestamp']
            window_end = window_start + timedelta(minutes=window_minutes)
            
            # Count events in window
            events_in_window = [
                e for e in source_events 
                if window_start <= e['timestamp'] <= window_end
            ]
            
            if len(events_in_window) >= threshold:
                # Get unique usernames targeted
                usernames = list(set(e['username'] for e in events_in_window))
                
                alert = {
                    'severity': 'HIGH',
                    'rule': 'Brute Force Attempt',
                    'description': f"{len(events_in_window)} failed logins from {source_ip} within {window_minutes} min (targeting: {', '.join(usernames)})",
                    'source_ip': source_ip,
                    'timestamp': window_start,
                    'event_count': len(events_in_window)
                }
                
                # Avoid duplicate alerts for same source
                if not any(a['source_ip'] == source_ip and a['rule'] == 'Brute Force Attempt' for a in alerts):
                    alerts.append(alert)
                break
    
    return alerts


def detect_off_hours_login(events: list, start_hour: int = 0, end_hour: int = 5) -> list:
    """
    Detect logins during off-hours (suspicious times).
    
    Default: 12:00 AM - 5:00 AM
    """
    alerts = []
    
    # Filter for successful logins (Event ID 4624)
    successful_logins = [e for e in events if e['event_id'] == 4624 and e['status'] == 'Success']
    
    for event in successful_logins:
        hour = event['timestamp'].hour
        
        if start_hour <= hour < end_hour:
            alert = {
                'severity': 'MEDIUM',
                'rule': 'Off-Hours Login',
                'description': f"Successful login by '{event['username']}' from {event['source_ip']} at {event['timestamp'].strftime('%H:%M:%S')}",
                'source_ip': event['source_ip'],
                'username': event['username'],
                'timestamp': event['timestamp']
            }
            alerts.append(alert)
    
    return alerts


def detect_privilege_escalation(events: list) -> list:
    """
    Detect privilege escalation events.
    
    Watches for users being added to privileged groups.
    Event IDs: 4728, 4732, 4756 (group membership changes)
    """
    alerts = []
    
    # Event IDs for group membership changes
    priv_esc_events = [4728, 4732, 4756]
    
    for event in events:
        if event['event_id'] in priv_esc_events:
            alert = {
                'severity': 'HIGH',
                'rule': 'Privilege Escalation',
                'description': f"User '{event['username']}' added to privileged group (Event ID: {event['event_id']}) from {event['source_ip']}",
                'source_ip': event['source_ip'],
                'username': event['username'],
                'timestamp': event['timestamp']
            }
            alerts.append(alert)
    
    # Also check for account lockouts (Event ID 4740)
    for event in events:
        if event['event_id'] == 4740:
            alert = {
                'severity': 'MEDIUM',
                'rule': 'Account Lockout',
                'description': f"Account '{event['username']}' was locked out",
                'username': event['username'],
                'timestamp': event['timestamp']
            }
            alerts.append(alert)
    
    return alerts


def run_detections(events: list, config: dict) -> list:
    """Run all detection rules against parsed events."""
    all_alerts = []
    
    print("[*] Running detection rules...")
    
    # Brute force detection
    brute_force_alerts = detect_brute_force(
        events,
        threshold=config.get("brute_force_threshold", 5),
        window_minutes=config.get("brute_force_window", 5)
    )
    all_alerts.extend(brute_force_alerts)
    
    # Off-hours login detection
    off_hours_alerts = detect_off_hours_login(
        events,
        start_hour=config.get("off_hours_start", 0),
        end_hour=config.get("off_hours_end", 5)
    )
    all_alerts.extend(off_hours_alerts)
    
    # Privilege escalation detection
    priv_esc_alerts = detect_privilege_escalation(events)
    all_alerts.extend(priv_esc_alerts)
    
    return all_alerts


def output_terminal(alerts: list, events: list):
    """Output results to terminal."""
    print("\n" + "=" * 60)
    print("                    ANALYSIS RESULTS")
    print("=" * 60)
    print(f"  Total events parsed:  {len(events)}")
    print(f"  Alerts generated:     {len(alerts)}")
    
    # Count by severity
    high_count = len([a for a in alerts if a['severity'] == 'HIGH'])
    medium_count = len([a for a in alerts if a['severity'] == 'MEDIUM'])
    low_count = len([a for a in alerts if a['severity'] == 'LOW'])
    
    print(f"\n  Severity Breakdown:")
    print(f"    HIGH:   {high_count}")
    print(f"    MEDIUM: {medium_count}")
    print(f"    LOW:    {low_count}")
    print("=" * 60)
    
    if not alerts:
        print("\n[+] No suspicious activity detected.")
        return
    
    print("\n ALERTS:\n")
    
    for i, alert in enumerate(alerts, 1):
        severity = alert.get("severity", "UNKNOWN").upper()
        rule = alert.get("rule", "Unknown Rule")
        description = alert.get("description", "No description")
        timestamp = alert.get("timestamp", "")
        
        # Color coding for severity (ANSI codes)
        if severity == "HIGH":
            sev_display = f"\033[91m[{severity}]\033[0m"      # Red
        elif severity == "MEDIUM":
            sev_display = f"\033[93m[{severity}]\033[0m"    # Yellow
        else:
            sev_display = f"[{severity}]"
        
        print(f"  {i}. {sev_display} {rule}")
        print(f"     {description}")
        if timestamp:
            print(f"     Time: {timestamp}")
        print()


def output_html(alerts: list, events: list, output_dir: str):
    """Generate HTML report."""
    # TODO: Implement HTML report generation with Jinja2
    print(f"[*] HTML report generation not yet implemented")
    print(f"[*] Would save to: {output_dir}")


def output_csv(alerts: list, events: list, output_dir: str):
    """Generate CSV report."""
    # TODO: Implement CSV report generation
    print(f"[*] CSV report generation not yet implemented")
    print(f"[*] Would save to: {output_dir}")


def main():
    """Main entry point."""
    print_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Validate input file
    input_path = validate_input_file(args.input)
    
    # Load configuration
    config = load_config(args.config)
    
    # Parse log file based on type
    if args.type == "windows":
        events = parse_windows_log(input_path)
    else:
        events = parse_linux_log(input_path)
    
    # Run detection rules
    alerts = run_detections(events, config)
    
    # Generate output
    if args.report == "terminal":
        output_terminal(alerts, events)
    elif args.report == "html":
        output_html(alerts, events, args.output)
    elif args.report == "csv":
        output_csv(alerts, events, args.output)
    
    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    main()
