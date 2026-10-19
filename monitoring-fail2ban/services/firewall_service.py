import subprocess
import re


def get_firewall_status():

    data = {
        "status": "Inactive",
        "backend": "-",
        "incoming": "-",
        "outgoing": "-",
        "rules": []
    }

    try:

        result = subprocess.check_output(
            ["sudo", "ufw", "status", "verbose"],
            text=True
        )

        data["backend"] = "UFW"

        if "Status: active" in result:
            data["status"] = "Active"

        incoming = re.search(r"Default:\s+(\w+)", result)
        outgoing = re.search(r"Default:.*?,\s*(\w+)", result)

        if incoming:
            data["incoming"] = incoming.group(1)

        if outgoing:
            data["outgoing"] = outgoing.group(1)

        lines = result.splitlines()

        start = False

        for line in lines:

            if "To" in line and "Action" in line:

                start = True
                continue

            if start:

                if line.strip() == "":
                    continue

                parts = line.split()

                if len(parts) >= 3:

                    data["rules"].append({

                        "port": parts[0],

                        "action": parts[1],

                        "from": " ".join(parts[2:])

                    })

    except:

        pass

    return data
