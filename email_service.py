import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def send_email(recipient_email, subject, body):
    """
    Sends an email using SMTP settings from environment variables.
    """
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM")

    if not all([smtp_server, smtp_port, smtp_username, smtp_password, email_from]):
        raise ValueError("Missing SMTP configuration in environment variables.")

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the server and send the email
        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.starttls()  # Secure the connection
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        raise e
