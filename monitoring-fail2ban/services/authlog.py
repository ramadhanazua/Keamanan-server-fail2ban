import re

LOG_FILE = "/var/log/auth.log"


def get_recent_logs(limit=50):

    logs = []

    try:

        with open(LOG_FILE, "r") as f:

            lines = f.readlines()[-limit:]

        for line in reversed(lines):

            if "Failed password" in line or "Invalid user" in line:

                ip = "-"

                username = "-"

                status = ""

                date = " ".join(line.split()[:3])

                if "Failed password" in line:

                    status = "Failed Password"

                    m = re.search(
                        r'Failed password for (invalid user )?(\S+) from ([0-9.]+)',
                        line
                    )

                    if m:

                        username = m.group(2)

                        ip = m.group(3)

                elif "Invalid user" in line:

                    status = "Invalid User"

                    m = re.search(
                        r'Invalid user (\S+) from ([0-9.]+)',
                        line
                    )

                    if m:

                        username = m.group(1)

                        ip = m.group(2)

                logs.append({

                    "date": date,

                    "ip": ip,

                    "username": username,

                    "status": status

                })

    except:

        pass

    return logs
