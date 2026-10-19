from flask import Blueprint
from flask import render_template

from flask_login import login_required

from services.firewall_service import get_firewall_status

from services.authlog import get_recent_logs

monitoring = Blueprint("monitoring", __name__)


@monitoring.route("/monitoring")
@login_required
def monitoring_page():

    logs = get_recent_logs()

    return render_template(

        "monitoring.html",

        logs=logs

    )


@monitoring.route("/firewall")
@login_required
def firewall():

    firewall = get_firewall_status()

    return render_template(
        "firewall.html",
        firewall=firewall
    )
