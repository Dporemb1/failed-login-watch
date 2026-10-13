"""
failed_logins.py
Reads a Linux auth.log and reports failed SSH login attempts.
"""
import argparse
import re
from collections import Counter
import csv

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")


def parse_log(path):
    attempts = []
    with open(path) as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.groups()
                attempts.append((user, ip))
    return attempts


def main():
    parser = argparse.ArgumentParser(description="Report failed SSH logins")
    parser.add_argument("logfile", help="path to auth.log")
    parser.add_argument("--threshold", type=int, default=3,
                        help="only show IPs with at least this many failures")
    parser.add_argument("--csv", help="also save results to this CSV file")
    args = parser.parse_args()

    attempts = parse_log(args.logfile)
    counts = Counter(ip for _, ip in attempts)
    print(f"Total failed logins: {len(attempts)}")
    print(f"IPs with {args.threshold}+ failures:")
    for ip, n in counts.most_common():
        if n >= args.threshold:
            print(f"  {ip:<16} {n} attempts")

        if args.csv:
           with open(args.csv, "w", newline="") as f:
               writer = csv.writer(f)
               writer.writerow(["ip", "user"])
               writer.writerows((ip, user) for user, ip in attempts)
           print(f"Saved to {args.csv}")


if __name__ == "__main__":
    main()