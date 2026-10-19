# services/audit_service.py
import subprocess
import re
from datetime import datetime, timedelta

SUDO = "/usr/bin/sudo"
AUSEARCH = "/usr/sbin/ausearch"

IGNORED_PROCESSES = [
    "auditctl",
    "chown",
    "chmod",
    "systemctl",
    "auditd",
]

# ==========================================================
# AUID YANG DIABAIKAN (tidak ditampilkan di dashboard)
# ==========================================================
IGNORED_AUID = [
    "ramadhanazua",   # Admin — bukan target serangan
    "root",           # Root — bukan target serangan
    "admin",          # Admin lain
    "unset",          # Auid tidak valid
    "4294967295",     # Auid tidak valid
]

AUDIT_KEY = "iso_access"
RETENTION_HOURS = 24


def parse_audit_timestamp(timestamp_str):
    """Parse timestamp dari audit log"""
    try:
        timestamp_str = timestamp_str.strip()

        # Format: 09/19/2026 16:16:37.190:550
        if '/' in timestamp_str:
            match = re.search(r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})', timestamp_str)
            if match:
                return datetime.strptime(match.group(1), '%m/%d/%Y %H:%M:%S')

        # Format: Thu Sep 10 20:15:23 2026
        if '->' in timestamp_str:
            timestamp_str = timestamp_str.split('->')[1].strip()

        return datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
    except Exception as e:
        print(f"[TIMESTAMP PARSE ERROR] {timestamp_str}: {e}")
        return None


def is_within_retention(timestamp_str, hours=RETENTION_HOURS):
    """Cek apakah timestamp dalam rentang N jam terakhir"""
    dt = parse_audit_timestamp(timestamp_str)
    if not dt:
        return True
    cutoff = datetime.now() - timedelta(hours=hours)
    return dt >= cutoff


def get_audit_events():
    """Ambil event Auditd untuk key iso_access"""

    command = [SUDO, "-n", AUSEARCH, "-k", AUDIT_KEY, "-i"]
    print("[AUDIT COMMAND]", " ".join(command))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False
        )

        if result.returncode != 0:
            print("[AUDIT STDERR]", result.stderr.strip())
            return []

        output = result.stdout
        events = []

        # Split by event (dipisah oleh "----")
        raw_events = output.split("----")

        for raw_event in raw_events:
            raw_event = raw_event.strip()
            if not raw_event:
                continue

            event = parse_single_event(raw_event)
            if event:
                events.append(event)

        # Event terbaru di atas
        events.reverse()
        events = events[:100]

        print(f"[AUDIT EVENTS] {len(events)} events (last {RETENTION_HOURS} hours)")
        return events

    except subprocess.TimeoutExpired:
        print("[AUDIT TIMEOUT]")
        return []
    except Exception as e:
        print("[AUDIT EXCEPTION]", repr(e))
        import traceback
        traceback.print_exc()
        return []


def parse_single_event(raw_event):
    """Parse satu event audit"""
    try:
        # ==================================================
        # 1. AMBIL TIMESTAMP
        # ==================================================
        event_time = ""

        time_match = re.search(r'time->(.+)', raw_event)
        if time_match:
            event_time = time_match.group(1).strip()

        if not event_time:
            audit_match = re.search(r'audit\(([^)]+)\)', raw_event)
            if audit_match:
                event_time = audit_match.group(1).strip()

        # ==================================================
        # 2. FILTER RETENSI
        # ==================================================
        if event_time:
            if not is_within_retention(event_time, RETENTION_HOURS):
                return None

        # ==================================================
        # 3. PARSE SYSCALL
        # ==================================================
        auid = ""
        uid = ""
        process = ""
        syscall = ""
        success = ""

        syscall_match = re.search(r'type=SYSCALL\s+msg=audit\([^)]+\)\s*:\s*(.+)', raw_event)
        if syscall_match:
            syscall_line = syscall_match.group(1)

            auid_m = re.search(r'auid=([^\s]+)', syscall_line)
            uid_m = re.search(r'uid=([^\s]+)', syscall_line)
            comm_m = re.search(r'comm=([^\s]+)', syscall_line)
            syscall_m = re.search(r'syscall=([^\s]+)', syscall_line)
            success_m = re.search(r'success=([^\s]+)', syscall_line)

            if auid_m:
                auid = auid_m.group(1)
            if uid_m:
                uid = uid_m.group(1)
            if comm_m:
                process = comm_m.group(1).strip('"')
            if syscall_m:
                syscall = syscall_m.group(1)
            if success_m:
                success = success_m.group(1)

        # ==================================================
        # 4. FILTER PROSES
        # ==================================================
        if process in IGNORED_PROCESSES:
            return None

        # ==================================================
        # 5. FILTER AUID (hanya user biasa)
        # ==================================================
        if auid in IGNORED_AUID:
            return None

        if auid in ["unset", "4294967295", ""]:
            return None

        # ==================================================
        # 6. PARSE PATH (FILE)
        # ==================================================
        file_path = ""

        path_match = re.search(r'type=PATH\s+msg=audit\([^)]+\)\s*:\s*item=\d+\s+name=([^\s]+)', raw_event)
        if path_match:
            file_path = path_match.group(1).strip('"')

        if not file_path:
            name_match = re.search(r'name=([^\s"]+)', raw_event)
            if name_match:
                file_path = name_match.group(1).strip('"')

        # ==================================================
        # 7. FILTER: HANYA FILE DI /var/data/perusahaan
        # ==================================================
        if file_path and "/var/data/perusahaan" not in file_path:
            return None

        # ==================================================
        # 8. AMBIL NAMA FILE
        # ==================================================
        if file_path:
            # Hapus trailing slash
            file_path_clean = file_path.rstrip('/')

            if "/" in file_path_clean:
                filename = file_path_clean.split("/")[-1]
            else:
                filename = file_path_clean

            # Jika folder, tandai sebagai (folder)
            if filename == "perusahaan":
                filename = "perusahaan/ (folder)"
            elif not filename:
                filename = "-"
        else:
            filename = "-"

        # ==================================================
        # 9. FORMAT WAKTU
        # ==================================================
        time_formatted = event_time
        if event_time:
            dt = parse_audit_timestamp(event_time)
            if dt:
                time_formatted = dt.strftime("%d/%m/%Y %H:%M:%S")

        # ==================================================
        # 10. RETURN EVENT
        # ==================================================
        return {
            "time": event_time,
            "time_formatted": time_formatted,
            "auid": auid,
            "uid": uid,
            "process": process,
            "syscall": syscall,
            "success": success,
            "file": file_path,
            "filename": filename,
        }

    except Exception as e:
        print(f"[PARSE ERROR] {e}")
        return None


def get_iso_events():
    return get_audit_events()
