from pathlib import Path
from collections import defaultdict
import re


# ---------------------------------------------------
# File Location
# ---------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "logs" / "auth.log"


# ---------------------------------------------------
# Detection Thresholds
# ---------------------------------------------------

FAILED_LOGIN_THRESHOLD = 5
MULTIPLE_USER_THRESHOLD = 3


# ---------------------------------------------------
# Analyze IP Activity
# ---------------------------------------------------

def analyze_ip_activity():

    if not LOG_FILE.exists():
        print("Security log not found.")
        return


    ip_activity = defaultdict(
        lambda: {
            "failed_logins": 0,
            "successful_logins": 0,
            "usernames": set(),
            "account_lockouts": 0,
            "unauthorized_admin": 0,
            "csrf_blocks": 0,
            "rate_limits": 0
        }
    )


    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        for line in log_file:

            line = line.strip()

            if not line:
                continue


            ip_match = re.search(
                r"ip=([^\s]+)",
                line
            )

            username_match = re.search(
                r"user=([^\s]+)",
                line
            )


            if not ip_match:
                continue


            ip_address = ip_match.group(1)

            username = "unknown"

            if username_match:
                username = username_match.group(1)


            activity = ip_activity[ip_address]


            if username != "unknown":
                activity["usernames"].add(username)


            if "LOGIN_FAILED" in line:
                activity["failed_logins"] += 1


            if "LOGIN_SUCCESS" in line:
                activity["successful_logins"] += 1


            if "ACCOUNT_LOCKED" in line:
                activity["account_lockouts"] += 1


            if "UNAUTHORIZED_ADMIN_ACCESS" in line:
                activity["unauthorized_admin"] += 1


            if "CSRF_BLOCKED" in line:
                activity["csrf_blocks"] += 1


            if "RATE_LIMIT_EXCEEDED" in line:
                activity["rate_limits"] += 1


    # ---------------------------------------------------
    # Display Report
    # ---------------------------------------------------

    print()

    print("=" * 60)
    print("SECUREAUTH SUSPICIOUS IP DETECTOR")
    print("=" * 60)

    print()


    suspicious_found = False


    for ip_address, activity in ip_activity.items():

        risk_score = 0
        reasons = []


        # Failed login behavior
        if activity["failed_logins"] >= FAILED_LOGIN_THRESHOLD:

            risk_score += 3

            reasons.append(
                "High number of failed login attempts"
            )


        # Multiple targeted users
        if len(activity["usernames"]) >= MULTIPLE_USER_THRESHOLD:

            risk_score += 2

            reasons.append(
                "Multiple user accounts targeted"
            )


        # Account lockouts
        if activity["account_lockouts"] > 0:

            risk_score += 3

            reasons.append(
                "Account lockout triggered"
            )


        # Unauthorized admin access
        if activity["unauthorized_admin"] > 0:

            risk_score += 2

            reasons.append(
                "Unauthorized admin access attempted"
            )


        # CSRF violations
        if activity["csrf_blocks"] > 0:

            risk_score += 2

            reasons.append(
                "CSRF request blocked"
            )


        # Rate limiting
        if activity["rate_limits"] > 0:

            risk_score += 3

            reasons.append(
                "Rate limit triggered"
            )


        # ---------------------------------------------------
        # Risk Classification
        # ---------------------------------------------------

        if risk_score >= 7:
            risk_level = "HIGH"

        elif risk_score >= 4:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"


        # ---------------------------------------------------
        # Print Suspicious IP
        # ---------------------------------------------------

        if risk_score >= 4:

            suspicious_found = True

            print("SUSPICIOUS IP DETECTED")
            print("-" * 60)

            print(
                f"Source IP: {ip_address}"
            )

            print(
                f"Risk Score: {risk_score}"
            )

            print(
                f"Risk Level: {risk_level}"
            )

            print()

            print(
                f"Failed Logins: "
                f"{activity['failed_logins']}"
            )

            print(
                f"Successful Logins: "
                f"{activity['successful_logins']}"
            )

            print(
                f"Accounts Targeted: "
                f"{len(activity['usernames'])}"
            )

            print(
                f"Account Lockouts: "
                f"{activity['account_lockouts']}"
            )

            print(
                f"Unauthorized Admin Attempts: "
                f"{activity['unauthorized_admin']}"
            )

            print(
                f"CSRF Blocks: "
                f"{activity['csrf_blocks']}"
            )

            print(
                f"Rate Limits: "
                f"{activity['rate_limits']}"
            )

            print()

            print("Detection Reasons:")

            for reason in reasons:
                print(
                    f"  - {reason}"
                )

            print()

            print(
                "Recommended Action: "
                "Investigate the source IP and review "
                "related authentication activity."
            )

            print()


    if not suspicious_found:

        print(
            "No suspicious IP activity detected."
        )

        print()


    print("=" * 60)
    print("IP ANALYSIS COMPLETE")
    print("=" * 60)

    print()


# ---------------------------------------------------
# Run Detector
# ---------------------------------------------------

if __name__ == "__main__":

    analyze_ip_activity()