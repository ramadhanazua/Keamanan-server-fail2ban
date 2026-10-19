#!/usr/bin/env python3

import re
import os
import json
import time
import subprocess

from collections import defaultdict, deque, Counter
from datetime import datetime
from zoneinfo import ZoneInfo

from behavior_config import (
    AUTH_LOG,
    EVENT_LOG,
    HISTORY_FILE,
    TIMEZONE,
    WINDOW_SECONDS,
    ATTACK_THRESHOLD,
    JAIL_BRUTEFORCE,
    JAIL_DICTIONARY
)


# ============================================================
# CONFIG
# ============================================================

TZ = ZoneInfo(TIMEZONE)

attempt_history = defaultdict(deque)

processed_ips = set()


# ============================================================
# REGEX SSH
# ============================================================

SSH_FAILED_REGEX = re.compile(
    r"Failed password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history():

    if not os.path.exists(HISTORY_FILE):
        return set()

    try:

        with open(
            HISTORY_FILE,
            "r"
        ) as file:

            return set(
                json.load(file)
            )

    except Exception:

        return set()


processed_ips = load_history()


# ============================================================
# SAVE HISTORY
# ============================================================

def save_history():

    os.makedirs(
        os.path.dirname(HISTORY_FILE),
        exist_ok=True
    )

    with open(
        HISTORY_FILE,
        "w"
    ) as file:

        json.dump(
            list(processed_ips),
            file,
            indent=4
        )


# ============================================================
# PARSE AUTH.LOG
# ============================================================

def parse_line(line):

    match = SSH_FAILED_REGEX.search(line)

    if not match:
        return None

    username = match.group(
        "username"
    )

    ip = match.group(
        "ip"
    )

    return username, ip


# ============================================================
# CLEAN HISTORY
# ============================================================

def cleanup(ip, current_time):

    history = attempt_history[ip]

    while history:

        timestamp = history[0]["timestamp"]

        if (
            current_time - timestamp
            > WINDOW_SECONDS
        ):

            history.popleft()

        else:

            break


# ============================================================
# SCORE
# ============================================================

def calculate_score(ip):

    history = attempt_history[ip]

    if not history:
        return None

    attempts = len(history)

    usernames = [
        item["username"]
        for item in history
    ]

    timestamps = [
        item["timestamp"]
        for item in history
    ]


    # --------------------------------------------------------
    # USERNAME
    # --------------------------------------------------------

    username_counter = Counter(
        usernames
    )

    unique_users = len(
        username_counter
    )


    most_common_username, \
    most_common_count = (
        username_counter.most_common(1)[0]
    )


    concentration = (
        most_common_count /
        attempts
    ) * 100


    diversity = (
        unique_users /
        attempts
    ) * 100


    # --------------------------------------------------------
    # FREQUENCY
    # --------------------------------------------------------

    if len(timestamps) > 1:

        duration = max(
            timestamps[-1]
            - timestamps[0],
            1
        )

    else:

        duration = 1


    rate = (
        attempts /
        duration
    )


    if rate >= 5:

        frequency_score = 100

    elif rate >= 3:

        frequency_score = 80

    elif rate >= 1:

        frequency_score = 60

    elif rate >= 0.5:

        frequency_score = 40

    else:

        frequency_score = 20


    # --------------------------------------------------------
    # BURST
    # --------------------------------------------------------

    burst_score = 20

    if len(timestamps) >= 3:

        intervals = []

        for i in range(
            1,
            len(timestamps)
        ):

            delta = (
                timestamps[i]
                - timestamps[i - 1]
            )

            if delta >= 0:
                intervals.append(delta)


        if intervals:

            average_interval = (
                sum(intervals)
                /
                len(intervals)
            )


            if average_interval < 0.2:

                burst_score = 100

            elif average_interval < 0.5:

                burst_score = 80

            elif average_interval < 1:

                burst_score = 60

            elif average_interval < 2:

                burst_score = 40

            else:

                burst_score = 20


    # --------------------------------------------------------
    # VOLUME
    # --------------------------------------------------------

    if attempts >= 100:

        volume_score = 100

    elif attempts >= 50:

        volume_score = 80

    elif attempts >= 20:

        volume_score = 60

    elif attempts >= 10:

        volume_score = 40

    else:

        volume_score = 20


    # --------------------------------------------------------
    # BRUTE FORCE SCORE
    # --------------------------------------------------------

    brute_score = (

        frequency_score * 0.30

        +

        concentration * 0.30

        +

        burst_score * 0.20

        +

        volume_score * 0.20

    )


    # --------------------------------------------------------
    # DICTIONARY SCORE
    # --------------------------------------------------------

    dictionary_score = (

        frequency_score * 0.20

        +

        diversity * 0.35

        +

        (100 - concentration) * 0.25

        +

        burst_score * 0.10

        +

        volume_score * 0.10

    )


    # --------------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------------

    if (
        brute_score >= ATTACK_THRESHOLD
        and brute_score > dictionary_score
    ):

        attack_type = "Brute Force"

        final_score = brute_score

    elif (
        dictionary_score >= ATTACK_THRESHOLD
    ):

        attack_type = "Dictionary Attack"

        final_score = dictionary_score

    else:

        attack_type = "Suspicious"

        final_score = max(
            brute_score,
            dictionary_score
        )


    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    confidence = min(
        round(final_score, 2),
        100
    )


    return {

        "ip": ip,

        "attack_type": attack_type,

        "score": round(
            final_score,
            2
        ),

        "confidence": confidence,

        "attempts": attempts,

        "unique_usernames":
            unique_users,

        "top_username":
            most_common_username,

        "username_concentration":
            round(
                concentration,
                2
            ),

        "username_diversity":
            round(
                diversity,
                2
            ),

        "attempts_per_second":
            round(
                rate,
                2
            ),

        "frequency_score":
            round(
                frequency_score,
                2
            ),

        "burst_score":
            round(
                burst_score,
                2
            ),

        "volume_score":
            round(
                volume_score,
                2
            ),

        "timestamp":
            datetime.now(
                TZ
            ).isoformat()

    }


# ============================================================
# WRITE EVENT
# ============================================================

def save_event(event):

    os.makedirs(
        os.path.dirname(EVENT_LOG),
        exist_ok=True
    )

    with open(
        EVENT_LOG,
        "a"
    ) as file:

        file.write(
            json.dumps(
                event
            )
            + "\n"
        )


# ============================================================
# BAN IP
# ============================================================

def ban_ip(
    ip,
    attack_type
):

    if ip in processed_ips:
        return


    if attack_type == "Brute Force":

        jail = JAIL_BRUTEFORCE

    elif attack_type == "Dictionary Attack":

        jail = JAIL_DICTIONARY

    else:

        return


    try:

        result = subprocess.run(

            [
                "fail2ban-client",
                "set",
                jail,
                "banip",
                ip
            ],

            capture_output=True,

            text=True,

            timeout=10

        )


        if result.returncode == 0:

            print(
                f"[BAN] "
                f"{ip} -> {jail}"
            )

            processed_ips.add(
                ip
            )

            save_history()

        else:

            print(
                "[FAIL2BAN ERROR]",
                result.stderr
            )


    except Exception as error:

        print(
            "[BAN ERROR]",
            error
        )


# ============================================================
# PROCESS ATTEMPT
# ============================================================

def process_attempt(
    username,
    ip
):

    now = time.time()


    attempt_history[ip].append({

        "timestamp": now,

        "username": username

    })


    cleanup(
        ip,
        now
    )


    result = calculate_score(
        ip
    )


    if not result:
        return


    save_event(
        result
    )


    print(
        f"[{result['attack_type']}] "
        f"{ip} | "
        f"score={result['score']} | "
        f"confidence={result['confidence']}% | "
        f"attempts={result['attempts']} | "
        f"users={result['unique_usernames']}"
    )


    if result["attack_type"] in (
        "Brute Force",
        "Dictionary Attack"
    ):

        ban_ip(
            ip,
            result["attack_type"]
        )


# ============================================================
# MONITOR AUTH.LOG
# ============================================================

def monitor_log():

    print(
        "========================================"
    )

    print(
        " Behavior Score Engine"
    )

    print(
        " SSH Behavioral Analysis"
    )

    print(
        "========================================"
    )

    print(
        f"Log : {AUTH_LOG}"
    )

    print(
        f"Window : {WINDOW_SECONDS} seconds"
    )

    print(
        "Status : RUNNING"
    )

    print()


    with open(
        AUTH_LOG,
        "r",
        errors="ignore"
    ) as file:

        file.seek(
            0,
            os.SEEK_END
        )


        while True:

            line = file.readline()


            if not line:

                time.sleep(
                    0.5
                )

                continue


            parsed = parse_line(
                line
            )


            if not parsed:

                continue


            username, ip = parsed


            process_attempt(
                username,
                ip
            )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    monitor_log()
