from flask import Blueprint
from flask import render_template
from flask import redirect
from flask import url_for

from services.fail2ban_service import (
    JAILS,
    get_jail_data,
    get_all_banned,
    run_fail2ban
)


fail2ban = Blueprint(
    "fail2ban",
    __name__
)


@fail2ban.route("/fail2ban")
def index():

    jail_data = get_jail_data()

    attackers = get_all_banned()

    total_banned = sum(
        jail["currently_banned"]
        for jail in jail_data
    )

    total_failed = sum(
        jail["total_failed"]
        for jail in jail_data
    )

    return render_template(
        "fail2ban.html",
        jails=jail_data,
        attacker=attackers,
        total=len(attackers),
        banned=total_banned,
        failed=total_failed,
        jail=len(jail_data)
    )


@fail2ban.route(
    "/unban/<jail>/<ip>"
)
def unban(jail, ip):

    if jail not in JAILS:

        return redirect(
            url_for(
                "fail2ban.index"
            )
        )

    run_fail2ban(
        "set",
        jail,
        "unbanip",
        ip
    )

    return redirect(
        url_for(
            "fail2ban.index"
        )
    )
