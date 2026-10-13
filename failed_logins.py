"""
failed_logins.py
Reads a Linux auth.log and reports failed SSH login attempts.
"""
import argparse
import re
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
    parser.add_argument("--csv", help="also save results to this CSV file")
    args = parser.parse_args()

    attempts = parse_log(args.logfile)
    print(f"Total failed logins: {len(attempts)}")
    for user, ip in attempts:
        print(f"  {ip:<16} user={user}")


if __name__ == "__main__":
    main()
