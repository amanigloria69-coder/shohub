"""Run once:  py create_admin.py   (creates the first Administrator)."""
import sqlite3
from werkzeug.security import generate_password_hash
from app import DATABASE, init_db

init_db()
email = input("Admin email [admin@shophub.com]: ").strip().lower() or "admin@shophub.com"
pw = input("Admin password (8+ chars, letters+numbers): ")   # visible so you can see what you type
if len(pw) < 8:
    raise SystemExit("Password too short.")
with sqlite3.connect(DATABASE) as db:
    try:
        db.execute("INSERT INTO users (full_name,email,password_hash,role,email_verified) VALUES (?,?,?,'admin',1)",
                   ("Administrator", email, generate_password_hash(pw)))
        print("Admin created:", email)
    except sqlite3.IntegrityError:
        print("That email already exists.")
