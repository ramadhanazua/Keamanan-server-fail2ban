import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "security_lab.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)

    count = conn.execute(
        "SELECT COUNT(*) AS total FROM employees"
    ).fetchone()["total"]

    if count == 0:
        conn.executemany("""
            INSERT INTO employees
            (name, department, email)
            VALUES (?, ?, ?)
        """, [
            ("Ahmad", "IT", "ahmad@dummy.local"),
            ("Budi", "Finance", "budi@dummy.local"),
            ("Citra", "Human Resource", "citra@dummy.local"),
            ("Dedi", "Engineering", "dedi@dummy.local"),
            ("Eka", "Front Office", "eka@dummy.local")
        ])

    conn.commit()
    conn.close()
