import subprocess
import re


JAILS = {
    "sshd-bruteforce": "Brute Force",
    "sshd-dictionary": "Dictionary Attack"
}


FAIL2BAN = "/usr/bin/fail2ban-client"
SUDO = "/usr/bin/sudo"


def run_fail2ban(*args):

    command = [
        SUDO,
        "-n",
        FAIL2BAN,
        *args
    ]

    print("[FAIL2BAN COMMAND]", command)

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False
        )

        print(
            "[FAIL2BAN RETURN CODE]",
            result.returncode
        )

        if result.stderr:
            print(
                "[FAIL2BAN STDERR]",
                result.stderr.strip()
            )

        if result.returncode != 0:
            return None

        return result.stdout

    except subprocess.TimeoutExpired:
        print(
            "[FAIL2BAN TIMEOUT]",
            command
        )
        return None

    except Exception as e:
        print(
            "[FAIL2BAN EXCEPTION]",
            repr(e)
        )
        return None


def get_jail_status(jail):

    return run_fail2ban(
        "status",
        jail
    )


def parse_value(status, pattern):

    if not status:
        return None

    match = re.search(
        pattern,
        status
    )

    if match:
        return match.group(1).strip()

    return None


def get_banned_ips(status):

    value = parse_value(
        status,
        r"Banned IP list:\s*(.*)"
    )

    if not value:
        return []

    return value.split()


def get_jail_data():

    data = []

    for jail, attack_type in JAILS.items():

        print(
            "[FAIL2BAN] Checking:",
            jail
        )

        status = get_jail_status(jail)

        if not status:
            print(
                "[FAIL2BAN] No status:",
                jail
            )
            continue

        currently_failed = parse_value(
            status,
            r"Currently failed:\s*(\d+)"
        )

        total_failed = parse_value(
            status,
            r"Total failed:\s*(\d+)"
        )

        currently_banned = parse_value(
            status,
            r"Currently banned:\s*(\d+)"
        )

        total_banned = parse_value(
            status,
            r"Total banned:\s*(\d+)"
        )

        banned_ips = get_banned_ips(
            status
        )

        data.append({

            "jail": jail,

            "jenis": attack_type,

            "currently_failed":
                int(currently_failed or 0),

            "total_failed":
                int(total_failed or 0),

            "currently_banned":
                int(currently_banned or 0),

            "total_banned":
                int(total_banned or 0),

            "banned_ips":
                banned_ips

        })

    return data


def get_all_banned():

    attackers = []

    jail_data = get_jail_data()

    no = 1

    for jail in jail_data:

        for ip in jail["banned_ips"]:

            attackers.append({

                "no": no,

                "ip": ip,

                "jenis": jail["jenis"],

                "jail": jail["jail"],

                "status": "Blocked"

            })

            no += 1

    return attackers
