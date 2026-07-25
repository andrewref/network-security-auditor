"""
Gmail send tool.

Requires a `credentials.json` (OAuth client, download from Google Cloud
Console) in the project root. On first run this opens a browser to
authorize, then caches a `token.json` for subsequent runs. Neither file
should ever be committed, both are already in .gitignore.
"""

import base64
import os
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from langchain_core.tools import tool

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def get_gmail_service():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


@tool
def send_email(
    receiver_email: str,
    subject: str,
    body: str,
    attachment_path: str = "",
) -> str:
    """
    Send an email with an optional attachment using Gmail.
    """
    service = get_gmail_service()

    message = EmailMessage()
    message["To"] = receiver_email
    message["Subject"] = subject
    message.set_content(body)

    if attachment_path:
        with open(attachment_path, "rb") as f:
            data = f.read()

        filename = os.path.basename(attachment_path)
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)

    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    service.users().messages().send(userId="me", body={"raw": encoded_message}).execute()

    return f"Email sent successfully to {receiver_email}"
