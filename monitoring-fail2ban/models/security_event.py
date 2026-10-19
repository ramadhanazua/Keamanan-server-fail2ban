from extensions import db
from datetime import datetime


class SecurityEvent(db.Model):

    __tablename__ = "security_event"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    tanggal = db.Column(
        db.DateTime,
        default=datetime.now
    )

    username = db.Column(
        db.String(100),
        nullable=True
    )

    ip = db.Column(
        db.String(50),
        nullable=True
    )

    attack_type = db.Column(
        db.String(150),
        nullable=False
    )

    endpoint = db.Column(
        db.String(200),
        nullable=True
    )

    payload = db.Column(
        db.Text,
        nullable=True
    )

    file = db.Column(
        db.String(300),
        nullable=True
    )

    process = db.Column(
        db.String(100),
        nullable=True
    )

    syscall = db.Column(
        db.String(100),
        nullable=True
    )

    access = db.Column(
        db.String(50),
        nullable=True
    )

    status = db.Column(
        db.String(50),
        nullable=True
    )

    action = db.Column(
        db.String(100),
        nullable=True
    )

    risk = db.Column(
        db.String(30),
        nullable=True
    )
