"""Email alerts: tell the customer about a problem without them opening the dashboard.

There are two separate things here, kept apart on purpose:

  * WHERE an alert goes - each organisation sets its own destination address.
    That lives in the database (per org, like every other piece of customer data).
  * The OUTBOX Aegis sends THROUGH - one mail account the operator configures
    once. Those are SECRETS (a password), so they live in a gitignored file
    (`aegis.env`) or real environment variables - never in the database, never
    in git.

No new dependency: Python's own smtplib + email + ssl do the work. In tests the
network send (`_transport`) is swapped for a fake, so no real mail is ever sent.

Configure the outbox by creating `aegis.env` next to the app (it is gitignored):

    AEGIS_SMTP_HOST=smtp-relay.brevo.com
    AEGIS_SMTP_PORT=587
    AEGIS_SMTP_USER=you@yourcompany.nl
    AEGIS_SMTP_PASSWORD=the-smtp-key
    AEGIS_SMTP_FROM=alerts@yourcompany.nl
    AEGIS_SMTP_SECURITY=starttls        # starttls | ssl | plain
    AEGIS_BASE_URL=http://127.0.0.1:8000
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

ENV_FILE = Path(os.environ.get("AEGIS_ENV_FILE", "aegis.env"))


def _load_env_file() -> None:
    """Read KEY=VALUE lines from a gitignored aegis.env (if present) into the
    environment, without overwriting anything already set in the real environment."""
    try:
        text = ENV_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def config() -> dict:
    """The current outbox settings. Reads aegis.env first, then the environment."""
    _load_env_file()
    host = os.environ.get("AEGIS_SMTP_HOST", "").strip()
    user = os.environ.get("AEGIS_SMTP_USER", "").strip()
    return {
        "host": host,
        "port": int(os.environ.get("AEGIS_SMTP_PORT", "587") or "587"),
        "user": user,
        "password": os.environ.get("AEGIS_SMTP_PASSWORD", ""),
        "from": os.environ.get("AEGIS_SMTP_FROM", "").strip() or user,
        "security": os.environ.get("AEGIS_SMTP_SECURITY", "starttls").strip().lower(),
        "base_url": os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:8000").strip(),
    }


def configured() -> bool:
    """True when the operator has set up an outbox (a host and a from-address)."""
    c = config()
    return bool(c["host"] and c["from"])


def _build(cfg: dict, to_addr: str, subject: str, body_lines: list[str]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from"]
    msg["To"] = to_addr
    text = "\n".join(body_lines).rstrip()
    text += f"\n\nOpen your dashboard: {cfg['base_url']}\n"
    text += ("\n--\nAegis attack-surface monitoring.\n"
             "You receive this because alert emails are enabled for your account.")
    msg.set_content(text)
    return msg


def _transport(cfg: dict, msg: EmailMessage) -> None:
    """The real network send. Tests replace this function, so no mail leaves in tests."""
    context = ssl.create_default_context()
    if cfg["security"] == "ssl":
        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=20) as s:
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
        return
    with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as s:
        if cfg["security"] == "starttls":
            s.starttls(context=context)
        if cfg["user"]:
            s.login(cfg["user"], cfg["password"])
        s.send_message(msg)


def _send(cfg: dict, msg: EmailMessage) -> None:
    if not cfg["host"] or not cfg["from"]:
        raise RuntimeError(
            "No email outbox is configured. Add AEGIS_SMTP_HOST / AEGIS_SMTP_FROM "
            "(and login details) to aegis.env, then restart Aegis.")
    _transport(cfg, msg)


def send_alert(to_addr: str, domain: str, level: str, title: str, lines: list[str]) -> None:
    """Email one alert. Raises if the outbox is not configured or the send fails."""
    cfg = config()
    tag = "Monitoring stopped" if level == "stopped" else "Security alert"
    body = [title, ""] + [f"- {ln}" for ln in lines]
    _send(cfg, _build(cfg, to_addr, f"[Aegis] {tag}: {domain}", body))


def send_test(to_addr: str) -> None:
    """Send a short test email so the customer can confirm delivery works."""
    cfg = config()
    body = ["This is a test email from Aegis.",
            "If you can read this, email alerts are set up correctly.",
            "You will get a message like this whenever monitoring finds a new problem."]
    _send(cfg, _build(cfg, to_addr, "[Aegis] Test alert", body))
