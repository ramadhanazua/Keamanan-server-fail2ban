from flask import Flask
from werkzeug.security import generate_password_hash

from extensions import db
from extensions import login_manager

from routes.monitoring import monitoring
from routes.fail2ban import fail2ban
from routes.security_events import security_events
from routes.audit import audit_bp
from routes.data_management import data_management
from routes.feedback import feedback

# ==========================================================
# IMPORT DOS DETECTION
# ==========================================================
from routes.dos_detection import dos_bp

# ==========================================================
# IMPORT ARP DETECTION
# ==========================================================
from routes.arp_detection import arp_bp

# ==========================================================
# IMPORT NMAP DETECTION
# ==========================================================
from routes.nmap_detection import nmap_bp

from data.security_lab import init_database


def create_app():

    app = Flask(__name__)

    # ==========================================================
    # KONFIGURASI
    # ==========================================================

    app.config.from_object("config.Config")

    # ==========================================================
    # DATABASE
    # ==========================================================

    db.init_app(app)

    # ==========================================================
    # FLASK LOGIN
    # ==========================================================

    login_manager.init_app(app)

    login_manager.login_view = "auth.login"

    # ==========================================================
    # USER LOADER
    # ==========================================================

    from models.user import User

    @login_manager.user_loader
    def load_user(user_id):

        try:

            return User.query.get(int(user_id))

        except (ValueError, TypeError):

            return None

    # ==========================================================
    # AUTHENTICATION
    # ==========================================================

    from routes.auth import auth

    app.register_blueprint(auth)

    # ==========================================================
    # DASHBOARD
    # ==========================================================

    from routes.dashboard import dashboard

    app.register_blueprint(dashboard)

    # ==========================================================
    # MONITORING
    # ==========================================================

    app.register_blueprint(monitoring)

    # ==========================================================
    # FAIL2BAN
    # ==========================================================

    app.register_blueprint(fail2ban)

    # ==========================================================
    # SECURITY EVENTS
    # ==========================================================

    app.register_blueprint(security_events)

    # ==========================================================
    # AUDIT
    # ==========================================================

    app.register_blueprint(audit_bp)

    # ==========================================================
    # DATA MANAGEMENT
    # ==========================================================

    app.register_blueprint(data_management)

    # ==========================================================
    # FEEDBACK / XSS TEST
    # ==========================================================

    app.register_blueprint(feedback)

    # ==========================================================
    # DOS DETECTION
    # ==========================================================

    app.register_blueprint(dos_bp)

    # ==========================================================
    # ARP DETECTION / MITM
    # ==========================================================

    app.register_blueprint(arp_bp)

    # ==========================================================
    # NMAP DETECTION
    # ==========================================================

    app.register_blueprint(nmap_bp)

    # ==========================================================
    # DATABASE INITIALIZATION
    # ==========================================================

    with app.app_context():

        # Membuat tabel SQLAlchemy
        db.create_all()

        # ------------------------------------------------------
        # Membuat administrator default
        # ------------------------------------------------------

        admin = User.query.filter_by(
            username="admin"
        ).first()

        if not admin:

            admin = User(

                username="admin",

                password=generate_password_hash(
                    "admin123"
                )

            )

            db.session.add(admin)

            db.session.commit()

            print(
                "[DATABASE] Admin berhasil dibuat."
            )

    # ==========================================================
    # INFORMASI ROUTE
    # ==========================================================

    print("")
    print("=" * 60)
    print(" LINUX SECURITY MONITORING SYSTEM")
    print("=" * 60)

    print("")
    print("Registered Routes:")

    for rule in app.url_map.iter_rules():

        print(
            f"  {rule.methods} -> {rule}"
        )

    print("")
    print("=" * 60)

    return app


# ==============================================================
# APPLICATION INSTANCE
# ==============================================================

app = create_app()


# ==============================================================
# RUN SERVER
# ==============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )
