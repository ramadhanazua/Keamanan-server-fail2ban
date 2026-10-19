from flask import Blueprint, render_template, request

from data.security_lab import get_connection
from services.web_security_service import (
    detect_sqli,
    create_event
)


data_management = Blueprint(
    "data_management",
    __name__
)


@data_management.route(
    "/data-management",
    methods=["GET", "POST"]
)
def index():

    keyword = ""
    results = []
    security_event = None

    if request.method == "POST":

        keyword = request.form.get(
            "keyword",
            ""
        ).strip()

        source_ip = request.remote_addr

        if detect_sqli(keyword):

            security_event = create_event(
                attack_type="SQL Injection",
                source_ip=source_ip,
                endpoint="/data-management",
                payload=keyword,
                action="BLOCKED",
                status="DETECTED"
            )

        else:

            conn = get_connection()

            results = conn.execute(
                """
                SELECT id, name, department, email
                FROM employees
                WHERE name LIKE ?
                   OR department LIKE ?
                """,
                (
                    f"%{keyword}%",
                    f"%{keyword}%"
                )
            ).fetchall()

            conn.close()

    return render_template(
        "data_management.html",
        results=results,
        keyword=keyword,
        security_event=security_event
    )
