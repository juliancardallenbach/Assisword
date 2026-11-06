"""Validación estricta de correos reales (anti-temporales + DNS MX) y envío de código OTP de 6 dígitos."""

from __future__ import annotations

import html
import json
import os
import re
import smtplib
import ssl
import sys
from email.message import EmailMessage
from typing import Dict, Optional, Tuple

import certifi
import httpx


def _outbound_transport() -> httpx.HTTPTransport:
    if sys.platform == "win32" and not os.environ.get("K_SERVICE"):
        return httpx.HTTPTransport(local_address="0.0.0.0", verify=certifi.where())
    return httpx.HTTPTransport(verify=certifi.where())

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$"
)

# Errores de tipeo frecuentes en dominios conocidos para avisarle al usuario antes de enviar
COMMON_DOMAIN_TYPOS = {
    "gmial.com": "gmail.com",
    "gamil.com": "gmail.com",
    "gmail.con": "gmail.com",
    "gmail.co": "gmail.com",
    "gmal.com": "gmail.com",
    "hotmial.com": "hotmail.com",
    "hotmail.con": "hotmail.com",
    "homtail.com": "hotmail.com",
    "outlok.com": "outlook.com",
    "outlook.con": "outlook.com",
    "yaho.com": "yahoo.com",
    "yahoo.con": "yahoo.com",
}

# Lista negra amplia de correos temporales / desechables ("10 minute mail", Yopmail, etc.)
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "10mail.org",
    "20minutemail.com", "33mail.com", "anonbox.net", "bccto.me", "burnermail.io",
    "chacuo.net", "crazymailing.com", "deadaddress.com", "discard.email",
    "discardmail.com", "dispostable.com", "dropmail.me", "emailondeck.com",
    "emailtemporario.com.br", "ephemail.net", "fakeinbox.com", "fakemail.net",
    "fakemailgenerator.com", "filzmail.com", "getairmail.com", "getnada.com",
    "grr.la", "guerrillamail.biz", "guerrillamail.com", "guerrillamail.de",
    "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "guerrillamailblock.com", "harakirimail.com", "inboxbear.com",
    "inboxkitten.com", "incognitomail.org", "jetable.org", "kasmail.com",
    "koszmail.pl", "kurzepost.de", "linshi-email.com", "luxusmail.org",
    "mail-temp.com", "mailcatch.com", "maildrop.cc", "mailexpire.com",
    "mailforspam.com", "mailinator.com", "mailinator.net", "mailinator2.com",
    "mailnesia.com", "mailnull.com", "mailsac.com", "mailtemp.info",
    "mailtothis.com", "meltmail.com", "mintemail.com", "mohmal.com",
    "moakt.com", "mt2015.com", "mytemp.email", "mytrashmail.com", "nada.email",
    "nada.ltd", "nervmich.net", "noclickemail.com", "nowmymail.com",
    "objectmail.com", "oneoffemail.com", "opayq.com", "owlpic.com",
    "pokemail.net", "proxymail.eu", "punkproof.com", "putthisinyourspamdatabase.com",
    "quickinbox.com", "rcpt.at", "recode.me", "regbypass.com", "rmqkr.net",
    "royal.net", "sharklasers.com", "shiftmail.com", "shortmail.net",
    "sibmail.com", "skeefmail.com", "slaskpost.se", "slipry.net", "spam4.me",
    "spamavert.com", "spambob.com", "spambog.com", "spambog.de", "spambog.ru",
    "spambox.us", "spamcero.com", "spamday.com", "spamex.com", "spamfree24.org",
    "spamgourmet.com", "spamherelots.com", "spamhole.com", "spaml.com",
    "spammotel.com", "spamobox.com", "spamspot.com", "superrito.com",
    "teleworm.us", "temp-mail.io", "temp-mail.org", "temp-mail.ru",
    "tempail.com", "tempalias.com", "tempe-mail.com", "tempemail.biz",
    "tempemail.co.za", "tempemail.com", "tempemail.net", "tempinbox.co.uk",
    "tempinbox.com", "tempmail.co", "tempmail.com", "tempmail.de",
    "tempmail.eu", "tempmail.it", "tempmail.net", "tempmail.org",
    "tempmail.plus", "tempmailaddress.com", "tempmailer.com", "tempmailo.com",
    "tempomail.fr", "temporarily.de", "temporarioemail.com.br",
    "temporaryemail.net", "temporaryemail.us", "temporaryforwarding.com",
    "temporaryinbox.com", "tempr.email", "throwam.com", "throwaway.email",
    "throwawaymail.com", "tmail.ws", "tmailinator.com", "tmpeml.info",
    "tmpmail.net", "tmpmail.org", "trash-mail.at", "trash-mail.com",
    "trash-mail.de", "trash2009.com", "trashdevil.com", "trashemail.de",
    "trashmail.at", "trashmail.com", "trashmail.de", "trashmail.io",
    "trashmail.me", "trashmail.net", "trashmail.org", "trashmailer.com",
    "trbvm.com", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "wh4f.org", "yopmail.com", "yopmail.fr", "yopmail.net", "zaktouni.fr",
}

_MX_CACHE: Dict[str, Tuple[bool, float]] = {}


def canonicalize_email(email: str) -> str:
    """Normaliza alias (+tag y puntos en Gmail) para impedir multicuentas con una misma casilla."""
    clean = (email or "").strip().lower()
    if "@" not in clean:
        return clean
    local, domain = clean.rsplit("@", 1)
    if domain == "googlemail.com":
        domain = "gmail.com"
    if "+" in local:
        local = local.split("+", 1)[0]
    if domain == "gmail.com":
        local = local.replace(".", "")
    return f"{local}@{domain}"


def verify_domain_has_mx(domain: str) -> bool:
    """Consulta en tiempo real por DNS-over-HTTPS si el dominio tiene servidores de correo (MX)."""
    import time

    dom = domain.strip().lower().rstrip(".")
    if not dom or dom.endswith(".local") or "." not in dom:
        return False

    cached = _MX_CACHE.get(dom)
    if cached and (time.time() - cached[1]) < 3600:
        return cached[0]

    endpoints = [
        f"https://dns.google/resolve?name={dom}&type=MX",
        f"https://cloudflare-dns.com/dns-query?name={dom}&type=MX",
    ]
    try:
        with httpx.Client(
            transport=_outbound_transport(),
            timeout=httpx.Timeout(connect=3.5, read=4.0, write=4.0, pool=4.0),
        ) as cli:
            for url in endpoints:
                try:
                    resp = cli.get(url, headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        data = resp.json()
                        status = data.get("Status", -1)
                        # Status 3 = NXDOMAIN (el dominio directamente NO existe)
                        if status == 3:
                            _MX_CACHE[dom] = (False, time.time())
                            return False
                        answers = data.get("Answer") or []
                        has_mx = any(
                            isinstance(a, dict) and a.get("type") == 15 and a.get("data", "").strip() not in ("", ".", "0 .")
                            for a in answers
                        )
                        if has_mx:
                            _MX_CACHE[dom] = (True, time.time())
                            return True
                        # Si no tiene MX, según RFC 5321 chequear si al menos existe registro A y no es nulo
                        resp_a = cli.get(
                            url.replace("type=MX", "type=A"),
                            headers={"Accept": "application/dns-json"},
                        )
                        if resp_a.status_code == 200:
                            ans_a = resp_a.json().get("Answer") or []
                            has_a = any(isinstance(a, dict) and a.get("type") == 1 for a in ans_a)
                            _MX_CACHE[dom] = (has_a, time.time())
                            return has_a
                except Exception:
                    continue
    except Exception:
        pass

    # Si ambos resolvedores DoH estuvieran inaccesibles por firewall, permitir continuar hacia el envío SMTP real
    return True


def validate_real_email_address(email: str) -> Tuple[bool, str]:
    """Valida sintaxis, errores comunes de tipeo, lista negra de mails descartables y registros MX reales."""
    clean = (email or "").strip().lower()
    if not clean:
        return False, "Ingresá tu dirección de correo electrónico."
    if len(clean) > 160 or not EMAIL_REGEX.match(clean):
        return False, "El formato del correo electrónico no es válido (ejemplo: nombre@gmail.com)."

    local, domain = clean.rsplit("@", 1)
    if len(local) < 2:
        return False, "La dirección de correo es demasiado corta o incompleta."

    if domain in COMMON_DOMAIN_TYPOS:
        sugerido = COMMON_DOMAIN_TYPOS[domain]
        return (
            False,
            f"Parece haber un error de escritura en '@{domain}'. ¿Quisiste poner '@{sugerido}'?",
        )

    # Revisar dominio exacto y subdominios de servicios temporales
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        sub = ".".join(parts[i:])
        if sub in DISPOSABLE_DOMAINS:
            return (
                False,
                "No se permiten correos temporales o desechables. Ingresá tu correo real (Gmail, Outlook, Hotmail, Yahoo, laboral, etc.).",
            )

    if not verify_domain_has_mx(domain):
        return (
            False,
            f"El dominio '@{domain}' no existe o no puede recibir correos electrónicos. Revisá que esté bien escrito.",
        )

    return True, "OK"


def build_verification_email_html(display_name: str, code: str, app_title: str = "Corrector de Documentos Pro") -> Tuple[str, str]:
    """Construye asunto, texto plano y HTML profesional con el código de 6 dígitos."""
    safe_name = html.escape(display_name or "Hola")
    spaced_code = f"{code[:3]} {code[3:]}"

    plain_body = (
        f"Hola {display_name or ''}:\n\n"
        f"Tu código de verificación para activar tu cuenta en {app_title} es:\n\n"
        f"    {code}\n\n"
        "Escribí estos 6 números en la ventana del programa para validar tu correo y habilitar tu prueba gratuita.\n"
        "Este código vence en 15 minutos.\n\n"
        "Si vos no solicitaste este código, podés ignorar este mensaje."
    )

    html_body = f"""<!DOCTYPE html>
<html lang="es">
<body style="margin:0;padding:24px;background-color:#F1F5F9;font-family:'Segoe UI',Arial,sans-serif;color:#1E293B;">
  <div style="max-width:520px;margin:0 auto;background:#FFFFFF;border-radius:12px;border:1px solid #CBD5E1;padding:28px;">
    <h2 style="margin:0 0 8px 0;color:#0F172A;font-size:20px;">Verificá tu correo electrónico</h2>
    <p style="margin:0 0 18px 0;color:#475569;font-size:14px;line-height:1.5;">
      Hola <strong>{safe_name}</strong>, ingresá el siguiente código de 6 dígitos en <strong>{html.escape(app_title)}</strong> para confirmar que este correo te pertenece:
    </p>
    <div style="background:#EFF6FF;border:2px dashed #2563EB;border-radius:10px;padding:18px;text-align:center;margin:20px 0;">
      <span style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#1D4ED8;font-family:Consolas,monospace;">{spaced_code}</span>
    </div>
    <p style="margin:0 0 10px 0;color:#64748B;font-size:13px;">
      ⏱ Este código es válido por <strong>15 minutos</strong>. Una vez verificado tu correo, se habilitará automáticamente tu prueba gratuita con instrucciones personalizadas.
    </p>
    <hr style="border:none;border-top:1px solid #E2E8F0;margin:18px 0;">
    <p style="margin:0;color:#94A3B8;font-size:12px;">
      Si no intentaste registrarte en {html.escape(app_title)}, simplemente ignorá este correo.
    </p>
  </div>
</body>
</html>"""
    return plain_body, html_body


def send_verification_code_email(
    to_email: str,
    display_name: str,
    code: str,
    mail_settings: Dict[str, str],
) -> Tuple[bool, str]:
    """Envía el correo real usando el canal configurado (Google Bridge HTTPS, SMTP o Brevo API).

    Devuelve (enviado_ok, detalle_o_error).
    """
    subject = f"{code} es tu código de verificación — Corrector Pro"
    plain_body, html_body = build_verification_email_html(display_name, code)
    from_name = (mail_settings.get("smtp_from_name") or "Corrector de Documentos Pro").strip()

    errors = []

    # CANAL 1: Puente Google Apps Script por HTTPS (100% gratis desde tu Gmail, funciona en Render/Cloud Run)
    bridge_url = (mail_settings.get("google_bridge_webhook_url") or "").strip()
    if bridge_url:
        try:
            with httpx.Client(
                transport=_outbound_transport(),
                timeout=httpx.Timeout(connect=6.0, read=18.0, write=10.0, pool=6.0),
                follow_redirects=True,
            ) as cli:
                resp = cli.post(
                    bridge_url,
                    json={
                        "action": "send_verification_email",
                        "to": to_email,
                        "subject": subject,
                        "plain_body": plain_body,
                        "html_body": html_body,
                        "sender_name": from_name,
                    },
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    if data.get("status") == "ok":
                        return True, "Correo enviado vía Google Gmail Bridge."
                    errors.append(f"Google Bridge: {data.get('message', 'error desconocido')}")
                elif resp.status_code in (401, 403):
                    errors.append(
                        f"Google Bridge HTTP {resp.status_code} (en Apps Script -> Implementar -> Gestionar implementaciones, "
                        "verificá que 'Quién tiene acceso' esté en 'Cualquier persona')"
                    )
                else:
                    errors.append(f"Google Bridge HTTP {resp.status_code}")
        except Exception as exc:
            errors.append(f"Google Bridge: {exc}")

    # CANAL 2: SMTP directo SSL / STARTTLS (ej. Gmail con Contraseña de Aplicación de 16 letras)
    smtp_user = (mail_settings.get("smtp_user") or "").strip()
    smtp_pass = (mail_settings.get("smtp_app_password") or "").strip().replace(" ", "")
    smtp_host = (mail_settings.get("smtp_host") or "smtp.gmail.com").strip()
    smtp_port_str = str(mail_settings.get("smtp_port") or "465").strip()
    if smtp_user and smtp_pass:
        try:
            port = int(smtp_port_str)
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = f"{from_name} <{smtp_user}>"
            msg["To"] = to_email
            msg.set_content(plain_body)
            msg.add_alternative(html_body, subtype="html")

            ctx = ssl.create_default_context(cafile=certifi.where())
            if port == 465:
                with smtplib.SMTP_SSL(smtp_host, port, timeout=15, context=ctx) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, port, timeout=15) as server:
                    server.ehlo()
                    server.starttls(context=ctx)
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            return True, "Correo enviado vía SMTP."
        except Exception as exc:
            errors.append(f"SMTP: {exc}")

    # CANAL 3: API HTTP de Brevo (300 correos/día gratis por HTTPS)
    brevo_key = (mail_settings.get("brevo_api_key") or "").strip()
    sender_email = smtp_user or (mail_settings.get("sender_email") or "").strip()
    if brevo_key and sender_email:
        try:
            with httpx.Client(
                transport=_outbound_transport(),
                timeout=httpx.Timeout(connect=6.0, read=12.0, write=10.0, pool=6.0),
            ) as cli:
                resp = cli.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={
                        "api-key": brevo_key,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json={
                        "sender": {"name": from_name, "email": sender_email},
                        "to": [{"email": to_email, "name": display_name or to_email}],
                        "subject": subject,
                        "htmlContent": html_body,
                        "textContent": plain_body,
                    },
                )
                if resp.status_code in (200, 201, 202):
                    return True, "Correo enviado vía Brevo API."
                errors.append(f"Brevo HTTP {resp.status_code}: {resp.text[:140]}")
        except Exception as exc:
            errors.append(f"Brevo: {exc}")

    if not errors:
        return (
            False,
            "El servidor aún no tiene configurado el remitente de correos (Gmail Bridge o SMTP). "
            "Entrá al Panel de Administrador (/admin) -> 'Envío de Correos' para activarlo en 1 minuto.",
        )

    return False, "No se pudo entregar el correo de verificación: " + " | ".join(errors)
