from flask import Blueprint, render_template

from models.security_event import SecurityEvent


security_events = Blueprint(
    "security_events",
    __name__
)


@security_events.route(
    "/security-events"
)
def index():

    events = (
        SecurityEvent.query
        .order_by(
            SecurityEvent.tanggal.desc()
        )
        .limit(100)
        .all()
    )

    return render_template(
        "security_events.html",
        events=events
    )
