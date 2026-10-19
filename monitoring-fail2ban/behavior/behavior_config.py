import os

BASE_DIR = os.path.abspath(
    os.path.dirname(os.path.dirname(__file__))
)

AUTH_LOG = "/var/log/auth.log"

EVENT_LOG = os.path.join(
    BASE_DIR,
    "behavior",
    "behavior_events.jsonl"
)

HISTORY_FILE = os.path.join(
    BASE_DIR,
    "behavior",
    "behavior_history.json"
)

TIMEZONE = "Asia/Jakarta"

WINDOW_SECONDS = 60

ATTACK_THRESHOLD = 60

JAIL_BRUTEFORCE = "sshd-bruteforce"

JAIL_DICTIONARY = "sshd-dictionary"
