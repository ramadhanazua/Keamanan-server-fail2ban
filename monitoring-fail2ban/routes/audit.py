# routes/audit.py
from flask import Blueprint, render_template
from services.audit_service import get_iso_events

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/audit")
def audit():
    events = get_iso_events()

    # Proses event untuk tampilan
    for event in events:
        # Status
        if event.get("success") == "yes":
            event["status"] = "ACCESS GRANTED"
            event["status_class"] = "warning"
        else:
            event["status"] = "ACCESS DENIED"
            event["status_class"] = "success"

        # Nama file saja
        file_path = event.get("file", "")
        if "/" in file_path:
            event["filename"] = file_path.split("/")[-1]
        else:
            event["filename"] = file_path

        # Process
        event["process"] = event.get("process", "N/A")

        # AUID
        event["auid"] = event.get("auid", "N/A")

        # Syscall
        event["syscall"] = event.get("syscall", "N/A")

    # Hitung statistik
    total = len(events)
    granted = sum(1 for e in events if e.get("success") == "yes")
    denied = total - granted

    return render_template(
        "audit.html",
        events=events,
        total=total,
        granted=granted,
        denied=denied
    )
