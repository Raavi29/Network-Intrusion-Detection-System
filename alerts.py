from __future__ import annotations

import json
import smtplib
from email.message import EmailMessage
from typing import Dict

import requests
from rich.console import Console

from .config import AlertConfig

console = Console()


class AlertManager:
    def __init__(self, config: AlertConfig):
        self.config = config

    def send(self, title: str, payload: Dict[str, object]) -> None:
        self._log_to_console(title, payload)
        if self.config.slack_webhook:
            self._send_slack(title, payload)
        if self.config.email_from and self.config.email_to:
            self._send_email(title, payload)

    def _log_to_console(self, title: str, payload: Dict[str, object]) -> None:
        console.log(f"[bold red]{title}[/bold red] {json.dumps(payload, default=str)}")

    def _send_slack(self, title: str, payload: Dict[str, object]) -> None:
        try:
            requests.post(
                self.config.slack_webhook,
                json={
                    "text": f"*{title}*\n```{json.dumps(payload, indent=2, default=str)}```"
                },
                timeout=5,
            )
        except requests.RequestException as exc:  # pragma: no cover
            console.log(f"[yellow]Slack alert failed:[/] {exc}")

    def _send_email(self, title: str, payload: Dict[str, object]) -> None:
        if not (self.config.smtp_server and self.config.smtp_port):
            console.log("[yellow]Skipping email alert; SMTP not configured[/]")
            return
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = self.config.email_from
        msg["To"] = self.config.email_to
        msg.set_content(json.dumps(payload, indent=2, default=str))
        try:
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=10) as smtp:
                if self.config.smtp_username and self.config.smtp_password:
                    smtp.starttls()
                    smtp.login(self.config.smtp_username, self.config.smtp_password)
                smtp.send_message(msg)
        except smtplib.SMTPException as exc:  # pragma: no cover
            console.log(f"[yellow]Email alert failed:[/] {exc}")



