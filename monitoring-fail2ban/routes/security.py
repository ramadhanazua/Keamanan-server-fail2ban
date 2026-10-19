from flask import Blueprint
from flask import render_template

from models.security_event import SecurityEvent

security = Blueprint(
    "security",
    __name__
)

@security.route("/security")

def security_log():

    data = SecurityEvent.query.order_by(
        SecurityEvent.id.desc()
    ).all()

    return render_template(

        "security.html",

        data=data

    )
