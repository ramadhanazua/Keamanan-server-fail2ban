from flask import Blueprint, render_template, request, redirect, url_for, flash

from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user

from models.user import User
from services.web_security_service import (
    detect_sqli,
    create_event
)

auth = Blueprint("auth", __name__)


@auth.route("/", methods=["GET", "POST"])
@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        source_ip = request.remote_addr

        # ==========================================
        # DETEKSI SQL INJECTION
        # ==========================================

        if detect_sqli(username) or detect_sqli(password):

            security_event = create_event(
                attack_type="SQL Injection",
                source_ip=source_ip,
                endpoint="/login",
                username=username,
                payload=f"username={username} | password=[FILTERED]",
                action="BLOCKED",
                status="DETECTED"
            )

            print("=" * 60)
            print("[SECURITY EVENT]")
            print("Attack    : SQL Injection")
            print("Source IP :", source_ip)
            print("Endpoint  : /login")
            print("Username  :", username)
            print("Payload   :", f"username={username} | password=[FILTERED]")
            print("Status    : DETECTED")
            print("Action    : BLOCKED")
            print("=" * 60)

            flash(
                "SQL Injection terdeteksi. Percobaan login telah diblokir.",
                "warning"
            )

            return render_template(
                "login.html",
                security_event=security_event
            ), 403

        # ==========================================
        # LOGIN NORMAL
        # ==========================================

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            return redirect(
                url_for("dashboard.home")
            )

        flash(
            "Username atau Password Salah",
            "danger"
        )

    return render_template("login.html")


@auth.route("/logout")
def logout():

    logout_user()

    return redirect(
        url_for("auth.login")
    )
