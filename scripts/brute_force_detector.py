from pathlib import Path
from collections import defaultdict
from datetime import datetime
import re


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "auth.log"


FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


def parse_failed_login(line):

    if "LOGIN_FAILED" not in line:
        return None

    timestamp_match = re.match(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        line
    )

    username_match = re.search(
        r"user=([^\s]+)",
        line
    )

    ip_match = re.search(
        r"ip=([^\s]+)",
        line
    )

    if not timestamp_match or not username_match or not ip_match:
        return None

    timestamp = datetime.strptime(
        timestamp_match.group(1),
        "%Y-%m-%d %H:%M:%S"
    )

    username = username_match.group(1)
    ip_address = ip_match.group(1)

    return timestamp, username, ip_address


def detect_brute_force():

    if not LOG_FILE.exists():
        print("Security log not found.")
        return

    failed_attempts = defaultdict(list)

    with open(LOG_FILE, "r") as log_file:

        for line in log_file:

            event = parse_failed_login(line)

            if event is None:
                continue

            timestamp, username, ip_address = event

            key = (ip_address, username)

            failed_attempts[key].append(timestamp)


    alerts_found = False

    print()
    print("=" * 55)
    print("SECUREAUTH BRUTE-FORCE DETECTOR")
    print("=" * 55)
    print()

    for (ip_address, username), timestamps in failed_attempts.items():

        timestamps.sort()

        for start_index in range(len(timestamps)):

            window_attempts = []

            start_time = timestamps[start_index]

            for timestamp in timestamps[start_index:]:

                difference = (
                    timestamp - start_time
                ).total_seconds()

                if difference <= TIME_WINDOW_SECONDS:
                    window_attempts.append(timestamp)

                else:
                    break

            if len(window_attempts) >= FAILED_ATTEMPT_THRESHOLD:

                alerts_found = True

                duration = (
                    window_attempts[-1]
                    - window_attempts[0]
                ).total_seconds()

                print("SECURITY ALERT")
                print("-" * 55)

                print("Type: Possible Brute-Force Attack")
                print(f"Source IP: {ip_address}")
                print(f"Target Account: {username}")
                print(
                    f"Failed Attempts: "
                    f"{len(window_attempts)}"
                )

                print(
                    f"Time Window: "
                    f"{int(duration)} seconds"
                )

                print("Severity: HIGH")

                print()
                print(
                    "Recommended Action: "
                    "Temporarily lock the account and investigate the source IP."
                )

                print()
                break


    if not alerts_found:

        print("No brute-force attacks detected.")

        print()
        print(
            f"Detection Rule: "
            f"{FAILED_ATTEMPT_THRESHOLD} failed attempts "
            f"within {TIME_WINDOW_SECONDS} seconds."
        )


    print()
    print("=" * 55)
    print("SCAN COMPLETE")
    print("=" * 55)
    print()


if __name__ == "__main__":
    detect_brute_force()