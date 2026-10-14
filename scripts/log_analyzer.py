from pathlib import Path
from collections import Counter
import re


# File Locations


BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "logs" / "auth.log"


# Parse Security Log

def analyze_logs():

    if not LOG_FILE.exists():
        print("Security log not found.")
        return

    event_counts = Counter()
    usernames = Counter()
    failed_usernames = Counter()
    ip_addresses = Counter()

    total_events = 0


    with open(LOG_FILE, "r") as log_file:

        for line in log_file:

            line = line.strip()

            if not line:
                continue

            total_events += 1


            # Extract event type

            event_match = re.search(
                r"(ACCOUNT_CREATED|LOGIN_SUCCESS|LOGIN_FAILED|LOGOUT|UNAUTHORIZED_ACCESS|ACCOUNT_LOCKED)",
                line
            )

            if event_match:

                event = event_match.group(1)

                event_counts[event] += 1


            # Extract username

            username_match = re.search(
                r"user=([^\s]+)",
                line
            )

            if username_match:

                username = username_match.group(1)

                usernames[username] += 1

                if "LOGIN_FAILED" in line:
                    failed_usernames[username] += 1


            # Extract IP address

            ip_match = re.search(
                r"ip=([^\s]+)",
                line
            )

            if ip_match:

                ip_address = ip_match.group(1)

                ip_addresses[ip_address] += 1


    # Display Report

    print()
    print("=" * 50)
    print("SECUREAUTH SECURITY REPORT")
    print("=" * 50)

    print()
    print(f"Total Security Events: {total_events}")

    print()
    print("EVENT SUMMARY")
    print("-" * 50)

    print(
        f"Account Creations:     "
        f"{event_counts['ACCOUNT_CREATED']}"
    )

    print(
        f"Successful Logins:     "
        f"{event_counts['LOGIN_SUCCESS']}"
    )

    print(
        f"Failed Logins:         "
        f"{event_counts['LOGIN_FAILED']}"
    )

    print(
        f"Logouts:               "
        f"{event_counts['LOGOUT']}"
    )

    print(
        f"Unauthorized Access:   "
        f"{event_counts['UNAUTHORIZED_ACCESS']}"
    )

    print(
        f"Locked Accounts:       "
        f"{event_counts['ACCOUNT_LOCKED']}"
    )


    print()
    print("NETWORK ACTIVITY")
    print("-" * 50)

    print(
        f"Unique IP Addresses: "
        f"{len(ip_addresses)}"
    )


    if ip_addresses:

        top_ip, top_ip_count = (
            ip_addresses.most_common(1)[0]
        )

        print(
            f"Most Active IP: "
            f"{top_ip} "
            f"({top_ip_count} events)"
        )


    print()
    print("AUTHENTICATION ANALYSIS")
    print("-" * 50)


    if failed_usernames:

        username, failure_count = (
            failed_usernames.most_common(1)[0]
        )

        print(
            f"Most Failed Username: "
            f"{username} "
            f"({failure_count} failures)"
        )

    else:

        print(
            "No failed authentication attempts detected."
        )


    print()
    print("=" * 50)
    print("ANALYSIS COMPLETE")
    print("=" * 50)
    print()


# Run Analyzer

if __name__ == "__main__":
    analyze_logs()
