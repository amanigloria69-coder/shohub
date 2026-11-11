"""Run:  py test_email.py   -> sends one test email using the MAIL_ settings in .env.
Tries port 587 and then 465 and tells you which one works on your network."""
import os, smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
load_dotenv()

to = input("Send a test email to: ").strip()
msg = EmailMessage()
msg["Subject"] = "ShopHub email test"
msg["From"] = os.environ["MAIL_FROM"]
msg["To"] = to
msg.set_content("It works! ShopHub can send emails.")
server = os.environ["MAIL_SERVER"]
user = os.environ["MAIL_USERNAME"]
password = os.environ["MAIL_PASSWORD"].replace(" ", "")

for port in (587, 465):
    try:
        if port == 465:
            with smtplib.SMTP_SSL(server, port, timeout=30) as s:
                s.login(user, password); s.send_message(msg)
        else:
            with smtplib.SMTP(server, port, timeout=30) as s:
                s.starttls(); s.login(user, password); s.send_message(msg)
        print(f"Sent using port {port}! Check the inbox (and Spam).")
        break
    except smtplib.SMTPAuthenticationError as e:
        print(f"Port {port}: the server refused the login - wrong App password? ({e})")
        break
    except Exception as e:
        print(f"Port {port} failed: {e}")
else:
    print("Both ports failed: check your internet connection, VPN, firewall or antivirus mail protection.")
