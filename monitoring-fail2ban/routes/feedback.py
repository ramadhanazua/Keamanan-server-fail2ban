from flask import Blueprint, render_template, request

from services.web_security_service import (
    detect_xss,
    create_event
)


feedback = Blueprint(
    "feedback",
    __name__
)


@feedback.route(
    "/feedback",
    methods=["GET", "POST"]
)
def index():

    name = ""
    message = ""
    security_event = None

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        message = request.form.get(
            "message",
            ""
        ).strip()

        source_ip = request.remote_addr

        if detect_xss(name) or detect_xss(message):

            security_event = create_event(
                attack_type="Cross-Site Scripting",
                source_ip=source_ip,
                endpoint="/feedback",
	        username=name,
                payload=message,
                action="BLOCKED",
                status="DETECTED"
            )

            name = ""
            message = ""

    return render_template(
        "feedback.html",
        name=name,
        message=message,
        security_event=security_event
    )
