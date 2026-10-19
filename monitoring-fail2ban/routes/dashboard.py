from flask import Blueprint, render_template
from flask_login import login_required

from services.system import get_server_info

dashboard = Blueprint("dashboard", __name__)

@dashboard.route("/dashboard")
@login_required
def home():

    server = get_server_info()

    return render_template(
        "dashboard.html",
        server=server
    )
