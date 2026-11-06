"""Núcleo comercial de Corrector Pro v2: Usuarios, OTP por correo real, HWID, Prueba Única, Plan Pro y Drive Sync."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import certifi
import httpx


def _outbound_transport() -> httpx.HTTPTransport:
    if sys.platform == "win32" and not os.environ.get("K_SERVICE"):
        return httpx.HTTPTransport(local_address="0.0.0.0", verify=certifi.where())
    return httpx.HTTPTransport(verify=certifi.where())

from email_verifier import (
    canonicalize_email,
    send_verification_code_email,
    validate_real_email_address,
)

logger = logging.getLogger("corrector-pro-server")


def _load_dotenv_file() -> None:
    env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.is_file():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


_load_dotenv_file()


def _resolve_data_dir() -> Path:
    candidates = []
    if os.environ.get("CORRECTOR_DATA_DIR"):
        candidates.append(Path(os.environ["CORRECTOR_DATA_DIR"]))
    if os.environ.get("K_SERVICE"):
        candidates.append(Path(tempfile.gettempdir()) / "corrector_pro_data")
    candidates.append(Path(__file__).resolve().parent / "server_data")
    candidates.append(Path(tempfile.gettempdir()) / "corrector_pro_data")

    for folder in candidates:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            probe = folder / ".write_ok"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return folder
        except Exception:
            continue
    return Path(tempfile.gettempdir())


DATA_DIR = _resolve_data_dir()
STATE_FILE = DATA_DIR / "corrector_pro_state.json"
SERVER_SECRET = os.environ.get(
    "SERVER_SECRET_KEY", "corrector-pro-v2-clave-firma-segura-2026"
)

OTP_EXPIRATION_SECONDS = 15 * 60  # 15 minutos
OTP_RESEND_COOLDOWN = 40          # 40 segundos entre reenvíos
OTP_MAX_ATTEMPTS = 5              # Máximo 5 intentos por código


def _hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        100_000,
    ).hex()


def _hash_otp(email: str, code: str) -> str:
    key = hashlib.sha256(SERVER_SECRET.encode("utf-8")).digest()
    msg = f"{email.lower().strip()}:{code.strip()}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def create_signed_token(email: str, role: str, hwid: str, days: int = 30) -> str:
    key = hashlib.sha256(SERVER_SECRET.encode("utf-8")).digest()
    payload = {
        "e": email.lower().strip(),
        "r": role,
        "h": (hwid or "")[:64],
        "exp": int(time.time()) + days * 86400,
    }
    raw_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    sig = hmac.new(key, raw_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw_b64}.{sig}"


def verify_signed_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    try:
        raw_b64, sig = token.split(".", 1)
        key = hashlib.sha256(SERVER_SECRET.encode("utf-8")).digest()
        expected = hmac.new(key, raw_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(raw_b64.encode("ascii")).decode("utf-8"))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def _try_load_local_dev_fallback_key() -> str:
    """En la PC del creador, si existe config.json de v1 con clave operativa, la usa como respaldo automático."""
    primary = os.environ.get("GEMINI_API_KEY", "").strip()
    candidates: List[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "CorrectorDocumentos" / "config.json")
    v1_root = Path(__file__).resolve().parents[2]
    candidates.append(v1_root / "config.json")
    candidates.append(v1_root / "dist" / "config.json")

    for cfg_p in candidates:
        if cfg_p.is_file():
            try:
                d = json.loads(cfg_p.read_text(encoding="utf-8-sig"))
                k = str(d.get("api_key", "")).strip()
                if k and k != primary:
                    return k
            except Exception:
                continue
    return ""


class CommercialServerManager:
    """Gestiona cuentas verificadas por mail, prueba única, suscripciones Pro y sincronización en la nube."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.state: Dict[str, Any] = {
            "service_enabled": True,
            "allow_registration": True,
            "default_monthly_doc_limit": 100,
            "default_max_devices": 2,
            "settings": {
                "gemini_api_key": os.environ.get("GEMINI_API_KEY", "").strip(),
                "gemini_fallback_api_key": (
                    os.environ.get("GEMINI_FALLBACK_API_KEY", "").strip()
                    or _try_load_local_dev_fallback_key()
                ),
                "google_bridge_webhook_url": os.environ.get("GOOGLE_BRIDGE_WEBHOOK_URL", "").strip(),
                "smtp_host": os.environ.get("SMTP_HOST", "smtp.gmail.com").strip(),
                "smtp_port": os.environ.get("SMTP_PORT", "465").strip(),
                "smtp_user": os.environ.get("SMTP_USER", "").strip(),
                "smtp_app_password": os.environ.get("SMTP_APP_PASSWORD", "").strip(),
                "smtp_from_name": os.environ.get("SMTP_FROM_NAME", "Corrector de Documentos Pro").strip(),
                "brevo_api_key": os.environ.get("BREVO_API_KEY", "").strip(),
                "mp_alias": os.environ.get("MP_ALIAS", "").strip(),
                "mp_payment_link": os.environ.get("MP_PAYMENT_LINK", "").strip(),
                "support_whatsapp": os.environ.get("SUPPORT_WHATSAPP", "").strip(),
                "pro_price_text": os.environ.get("PRO_PRICE_TEXT", "Plan Pro Mensual").strip(),
            },
            "users": {},               # email_lower -> user_dict
            "pending_otps": {},        # email_lower -> otp_dict
            "used_trial_emails": [],   # canonical emails que ya gastaron la prueba única
            "used_trial_hwids": [],    # HWIDs de PCs que ya gastaron la prueba única
            "stats": {
                "total_corrections": 0,
                "estimated_cost_usd": 0.0,
                "last_drive_sync": None,
            },
            "logs": [],
        }
        self._load_state()
        self._ensure_initial_admin()

    # ------------------------------------------------------------------
    # Persistencia local + Respaldo Google Drive
    # ------------------------------------------------------------------
    def _load_state(self) -> None:
        if STATE_FILE.is_file():
            try:
                loaded = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    # Preservar nuevas claves de settings que vengan de variables de entorno si estaban vacías
                    saved_settings = loaded.get("settings", {})
                    merged_settings = dict(self.state["settings"])
                    for k, v in saved_settings.items():
                        if str(v).strip() or not str(merged_settings.get(k, "")).strip():
                            merged_settings[k] = v
                    loaded["settings"] = merged_settings
                    self.state.update(loaded)
            except Exception as exc:
                logger.warning("Error cargando estado local: %s", exc)

        bridge_url = self.get_bridge_url()
        if bridge_url and not self.state.get("users"):
            self.pull_from_drive()

    def get_bridge_url(self) -> str:
        return str(self.state.get("settings", {}).get("google_bridge_webhook_url", "")).strip()

    def save_state(self, sync_drive: bool = True) -> None:
        with self._lock:
            try:
                STATE_FILE.write_text(
                    json.dumps(self.state, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.error("Error guardando estado: %s", exc)

        if sync_drive and self.get_bridge_url():
            threading.Thread(target=self._push_to_drive_bg, daemon=True).start()

    def _push_to_drive_bg(self) -> None:
        url = self.get_bridge_url()
        if not url:
            return
        try:
            with httpx.Client(
                transport=_outbound_transport(),
                timeout=httpx.Timeout(connect=6.0, read=18.0, write=10.0, pool=6.0),
                follow_redirects=True,
            ) as cli:
                resp = cli.post(
                    url,
                    json={
                        "action": "save_state",
                        "filename": "corrector_pro_state.json",
                        "data": self.state,
                    },
                )
                if resp.status_code in (200, 201):
                    self.state["stats"]["last_drive_sync"] = time.time()
        except Exception as exc:
            logger.warning("Aviso sincronizando con Drive: %s", exc)

    def pull_from_drive(self) -> bool:
        url = self.get_bridge_url()
        if not url:
            return False
        try:
            with httpx.Client(
                transport=_outbound_transport(),
                timeout=httpx.Timeout(connect=6.0, read=18.0, write=10.0, pool=6.0),
                follow_redirects=True,
            ) as cli:
                resp = cli.post(
                    url,
                    json={"action": "load_state", "filename": "corrector_pro_state.json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "ok" and isinstance(data.get("data"), dict):
                        remote_state = data["data"]
                        with self._lock:
                            saved_settings = remote_state.get("settings", {})
                            merged_settings = dict(self.state["settings"])
                            for k, v in saved_settings.items():
                                if str(v).strip() and not str(merged_settings.get(k, "")).strip():
                                    merged_settings[k] = v
                            remote_state["settings"] = merged_settings
                            self.state.update(remote_state)
                        self.save_state(sync_drive=False)
                        return True
        except Exception:
            pass
        return False

    def _ensure_initial_admin(self) -> None:
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@correctorpro.local").strip().lower()
        admin_pass = os.environ.get("ADMIN_INITIAL_PASSWORD", "admin1234").strip()
        users = self.state.setdefault("users", {})
        has_any_admin = any(u.get("role") == "admin" for u in users.values())
        if not has_any_admin and admin_email and admin_pass:
            salt = secrets.token_hex(16)
            users[admin_email] = {
                "email": admin_email,
                "canonical_email": canonicalize_email(admin_email),
                "display_name": "Administrador",
                "role": "admin",
                "password_hash": _hash_password(admin_pass, salt),
                "salt": salt,
                "email_verified": True,
                "verified_at": time.time(),
                "plan": "pro",
                "pro_expires_at": None,
                "free_trial_remaining": 999,
                "monthly_doc_limit": 99999,
                "docs_used_this_month": 0,
                "month_period_start": time.time(),
                "total_docs_corrected": 0,
                "estimated_cost_usd": 0.0,
                "max_devices": 10,
                "hwids": [],
                "is_blocked": False,
                "created_at": time.time(),
                "last_login": time.time(),
                "notes": "Cuenta administradora principal",
            }
            self.save_state(sync_drive=False)

    def log_event(self, email: str, action: str, ip: str = "", cost_usd: float = 0.0) -> None:
        entry = {
            "ts": time.time(),
            "email": email,
            "action": action,
            "ip": ip,
            "cost_usd": round(cost_usd, 5) if cost_usd else 0.0,
        }
        with self._lock:
            logs = self.state.setdefault("logs", [])
            logs.insert(0, entry)
            self.state["logs"] = logs[:150]

    # ------------------------------------------------------------------
    # Estado de plan y resumen para el cliente .exe
    # ------------------------------------------------------------------
    def _refresh_user_cycles(self, user: Dict[str, Any]) -> None:
        """Actualiza vencimiento de Plan Pro y reinicio mensual de cupo de documentos."""
        now = time.time()
        if user.get("role") == "admin":
            user["plan"] = "pro"
            return

        if user.get("plan") == "pro":
            exp = user.get("pro_expires_at")
            if exp is not None and exp < now:
                user["plan"] = "free"

        period_start = float(user.get("month_period_start") or now)
        if now - period_start >= 30 * 86400:
            user["docs_used_this_month"] = 0
            user["month_period_start"] = now

    def build_public_user_profile(self, user: Dict[str, Any], hwid: str = "") -> Dict[str, Any]:
        self._refresh_user_cycles(user)
        is_admin = user.get("role") == "admin"
        is_pro = is_admin or (user.get("plan") == "pro")

        hwid_clean = (hwid or "").strip()[:64]
        hwid_already_used_trial = bool(
            hwid_clean and hwid_clean in self.state.get("used_trial_hwids", [])
        )
        raw_trial = int(user.get("free_trial_remaining", 0))
        effective_trial = 0 if (hwid_already_used_trial and not is_pro) else raw_trial

        settings = self.state.get("settings", {})
        return {
            "email": user["email"],
            "display_name": user.get("display_name") or user["email"],
            "role": user.get("role", "user"),
            "email_verified": bool(user.get("email_verified", False)),
            "plan": "pro" if is_pro else "free",
            "pro_expires_at": user.get("pro_expires_at"),
            "free_trial_remaining": effective_trial,
            "hwid_trial_consumed": hwid_already_used_trial and raw_trial > 0,
            "docs_used_this_month": int(user.get("docs_used_this_month", 0)),
            "monthly_doc_limit": int(user.get("monthly_doc_limit", 100)),
            "total_docs_corrected": int(user.get("total_docs_corrected", 0)),
            "can_use_pro_features": bool(is_pro or effective_trial > 0),
            "payment_info": {
                "mp_alias": settings.get("mp_alias", ""),
                "mp_payment_link": settings.get("mp_payment_link", ""),
                "support_whatsapp": settings.get("support_whatsapp", ""),
                "pro_price_text": settings.get("pro_price_text", "Plan Pro"),
            },
        }

    # ------------------------------------------------------------------
    # Registro con envío REAL de código OTP al correo electrónico
    # ------------------------------------------------------------------
    def register_and_send_otp(
        self,
        email: str,
        password: str,
        display_name: str = "",
        hwid: str = "",
        ip: str = "",
    ) -> Tuple[bool, str, str]:
        """Inicia registro, valida correo real + MX y envía código de 6 dígitos al mail.

        Devuelve (ok, status_code_str, mensaje).
        """
        if not self.state.get("allow_registration", True):
            return False, "disabled", "El registro de nuevas cuentas está pausado temporalmente."

        clean_email = (email or "").strip().lower()
        ok_mail, msg_mail = validate_real_email_address(clean_email)
        if not ok_mail:
            return False, "invalid_email", msg_mail

        if not password or len(password) < 6:
            return False, "weak_password", "La contraseña debe tener al menos 6 caracteres."

        canon = canonicalize_email(clean_email)
        users = self.state.setdefault("users", {})

        # Verificar si ya existe cuenta verificada con este correo o un alias equivalente (+tag / puntos)
        for existing_email, u_rec in users.items():
            if existing_email == clean_email or u_rec.get("canonical_email") == canon:
                if u_rec.get("email_verified"):
                    return (
                        False,
                        "already_registered",
                        "Este correo electrónico ya está registrado. Iniciá sesión con tu contraseña.",
                    )
                # Si existía sin verificar aún, actualizamos su contraseña y reenviamos código
                clean_email = existing_email
                break

        # Control anti-spam de reenvío de OTP
        pending = self.state.setdefault("pending_otps", {}).get(clean_email)
        now = time.time()
        if pending and (now - float(pending.get("sent_at", 0))) < OTP_RESEND_COOLDOWN:
            faltan = int(OTP_RESEND_COOLDOWN - (now - float(pending["sent_at"])))
            return (
                False,
                "cooldown",
                f"Ya te enviamos un código hace unos segundos. Revisá tu bandeja de entrada o esperá {faltan} s para pedir otro.",
            )

        code = f"{secrets.randbelow(900000) + 100000:06d}"
        ok_send, send_detail = send_verification_code_email(
            to_email=clean_email,
            display_name=(display_name or clean_email.split("@")[0]).strip(),
            code=code,
            mail_settings=self.state.get("settings", {}),
        )
        if not ok_send:
            self.log_event(clean_email, f"Error enviando OTP: {send_detail[:80]}", ip=ip)
            self.save_state(sync_drive=False)
            return False, "mail_delivery_error", send_detail

        salt = secrets.token_hex(16)
        pw_hash = _hash_password(password, salt)

        # Determinar si este correo canónico ya consumió alguna vez la prueba única
        already_used_trial = (
            canon in self.state.get("used_trial_emails", [])
            or bool(hwid and hwid[:64] in self.state.get("used_trial_hwids", []))
        )

        with self._lock:
            users[clean_email] = {
                "email": clean_email,
                "canonical_email": canon,
                "display_name": (display_name or clean_email.split("@")[0]).strip()[:60],
                "role": "user",
                "password_hash": pw_hash,
                "salt": salt,
                "email_verified": False,
                "verified_at": None,
                "plan": "free",
                "pro_expires_at": None,
                "free_trial_remaining": 0 if already_used_trial else 1,
                "monthly_doc_limit": int(self.state.get("default_monthly_doc_limit", 100)),
                "docs_used_this_month": 0,
                "month_period_start": now,
                "total_docs_corrected": 0,
                "estimated_cost_usd": 0.0,
                "max_devices": int(self.state.get("default_max_devices", 2)),
                "hwids": [],
                "is_blocked": False,
                "created_at": now,
                "last_login": None,
                "notes": "",
            }
            self.state["pending_otps"][clean_email] = {
                "otp_hash": _hash_otp(clean_email, code),
                "expires_at": now + OTP_EXPIRATION_SECONDS,
                "sent_at": now,
                "attempts": 0,
            }

        self.log_event(clean_email, "Código de verificación OTP enviado al correo", ip=ip)
        self.save_state(sync_drive=True)
        return (
            True,
            "otp_sent",
            f"Te enviamos un código de 6 dígitos a {clean_email}. Entrá a tu correo (revisá también Promociones/Spam) y escribilo abajo.",
        )

    def resend_otp(self, email: str, ip: str = "") -> Tuple[bool, str]:
        clean_email = (email or "").strip().lower()
        user = self.state.get("users", {}).get(clean_email)
        if not user:
            return False, "No encontramos un registro pendiente con ese correo."
        if user.get("email_verified"):
            return False, "Ese correo ya está verificado. Podés iniciar sesión directamente."

        now = time.time()
        pending = self.state.setdefault("pending_otps", {}).get(clean_email)
        if pending and (now - float(pending.get("sent_at", 0))) < OTP_RESEND_COOLDOWN:
            faltan = int(OTP_RESEND_COOLDOWN - (now - float(pending["sent_at"])))
            return False, f"Esperá {faltan} segundos antes de volver a enviar el código."

        code = f"{secrets.randbelow(900000) + 100000:06d}"
        ok_send, send_detail = send_verification_code_email(
            to_email=clean_email,
            display_name=user.get("display_name", ""),
            code=code,
            mail_settings=self.state.get("settings", {}),
        )
        if not ok_send:
            return False, send_detail

        with self._lock:
            self.state["pending_otps"][clean_email] = {
                "otp_hash": _hash_otp(clean_email, code),
                "expires_at": now + OTP_EXPIRATION_SECONDS,
                "sent_at": now,
                "attempts": 0,
            }
        self.log_event(clean_email, "Reenvío de código OTP al correo", ip=ip)
        self.save_state(sync_drive=False)
        return True, f"Enviamos un nuevo código de 6 dígitos a {clean_email}."

    def verify_email_otp(
        self,
        email: str,
        code: str,
        hwid: str = "",
        ip: str = "",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Valida los 6 dígitos enviados al mail real y activa la cuenta."""
        clean_email = (email or "").strip().lower()
        clean_code = "".join(ch for ch in (code or "") if ch.isdigit())
        if len(clean_code) != 6:
            return False, "Ingresá los 6 números del código que llegó a tu correo.", None

        user = self.state.get("users", {}).get(clean_email)
        if not user:
            return False, "No se encontró una cuenta pendiente para ese correo.", None

        pending = self.state.get("pending_otps", {}).get(clean_email)
        if not pending:
            if user.get("email_verified"):
                return False, "Tu correo ya fue verificado. Iniciá sesión con tu contraseña.", None
            return False, "No hay un código activo. Tocá 'Reenviar código' para recibir uno nuevo.", None

        now = time.time()
        if now > float(pending.get("expires_at", 0)):
            return False, "El código venció (pasaron más de 15 minutos). Tocá 'Reenviar código'.", None

        attempts = int(pending.get("attempts", 0))
        if attempts >= OTP_MAX_ATTEMPTS:
            return False, "Superaste el máximo de intentos para este código. Pedí uno nuevo con 'Reenviar código'.", None

        expected_hash = pending.get("otp_hash", "")
        given_hash = _hash_otp(clean_email, clean_code)
        if not hmac.compare_digest(expected_hash, given_hash):
            with self._lock:
                pending["attempts"] = attempts + 1
            restantes = max(0, OTP_MAX_ATTEMPTS - (attempts + 1))
            self.save_state(sync_drive=False)
            return False, f"Código incorrecto. Te quedan {restantes} intento(s).", None

        # ¡Código válido! Activar correo y vincular primera PC
        hwid_clean = (hwid or "").strip()[:64]
        with self._lock:
            user["email_verified"] = True
            user["verified_at"] = now
            user["last_login"] = now
            if hwid_clean and hwid_clean not in user.setdefault("hwids", []):
                user["hwids"].append(hwid_clean)
            if hwid_clean and hwid_clean in self.state.get("used_trial_hwids", []):
                user["free_trial_remaining"] = 0
            self.state["pending_otps"].pop(clean_email, None)

        self.log_event(clean_email, "Correo electrónico verificado con éxito (OTP válido)", ip=ip)
        self.save_state(sync_drive=True)

        token = create_signed_token(clean_email, user.get("role", "user"), hwid_clean)
        return (
            True,
            "¡Correo verificado correctamente! Ya podés usar el programa.",
            {
                "token": token,
                "user": self.build_public_user_profile(user, hwid_clean),
            },
        )

    # ------------------------------------------------------------------
    # Inicio de sesión con control de verificación de mail + HWID
    # ------------------------------------------------------------------
    def login_user(
        self,
        email: str,
        password: str,
        hwid: str = "",
        ip: str = "",
    ) -> Tuple[bool, str, str, Optional[Dict[str, Any]]]:
        """Devuelve (ok, status_code, mensaje, data)."""
        clean_email = (email or "").strip().lower()
        user = self.state.get("users", {}).get(clean_email)
        if not user:
            return False, "not_found", "No existe una cuenta con ese correo. Tocá 'Crear cuenta gratis'.", None

        pw_hash = _hash_password(password or "", user["salt"])
        if not hmac.compare_digest(pw_hash, user["password_hash"]):
            self.log_event(clean_email, "Contraseña incorrecta al iniciar sesión", ip=ip)
            return False, "wrong_password", "Contraseña incorrecta.", None

        if not user.get("email_verified", False):
            return (
                False,
                "pending_verification",
                "Todavía falta ingresar el código de 6 dígitos que enviamos a tu correo para validar la cuenta.",
                {"email": clean_email},
            )

        if user.get("is_blocked") and user.get("role") != "admin":
            return (
                False,
                "blocked",
                "Tu cuenta se encuentra pausada por el Administrador. Comunicate con soporte.",
                None,
            )

        hwid_clean = (hwid or "").strip()[:64]
        if hwid_clean and user.get("role") != "admin":
            hwids = user.setdefault("hwids", [])
            max_dev = int(user.get("max_devices", 2))
            if hwid_clean not in hwids:
                if len(hwids) >= max_dev:
                    self.log_event(clean_email, f"Intento en PC extra bloqueado (límite {max_dev} equipos)", ip=ip)
                    return (
                        False,
                        "device_limit",
                        f"Esta cuenta ya está vinculada al máximo permitido de {max_dev} computadora(s). "
                        "Si cambiaste de PC, pedile al administrador que blanquee tus equipos.",
                        None,
                    )
                hwids.append(hwid_clean)

        with self._lock:
            user["last_login"] = time.time()
        self.log_event(clean_email, "Inicio de sesión exitoso", ip=ip)
        self.save_state(sync_drive=True)

        token = create_signed_token(clean_email, user.get("role", "user"), hwid_clean)
        return (
            True,
            "ok",
            "Sesión iniciada.",
            {
                "token": token,
                "user": self.build_public_user_profile(user, hwid_clean),
            },
        )

    # ------------------------------------------------------------------
    # Autorización y consumo de correcciones (Prueba Única vs Plan Pro)
    # ------------------------------------------------------------------
    def authorize_correction(
        self,
        token: str,
        hwid: str,
    ) -> Tuple[bool, str, str, Optional[Dict[str, Any]]]:
        """Verifica sesión, correo validado, HWID y derecho a usar funciones (Prueba única o Pro).

        Devuelve (autorizado, codigo_estado, mensaje, user_record).
        """
        if not self.state.get("service_enabled", True):
            return False, "maintenance", "El servicio está en mantenimiento momentáneo.", None

        claims = verify_signed_token(token)
        if not claims:
            return False, "unauthorized", "Tu sesión venció. Volvé a iniciar sesión.", None

        email = claims["e"]
        user = self.state.get("users", {}).get(email)
        if not user or not user.get("email_verified"):
            return False, "unauthorized", "Debés verificar tu correo electrónico antes de continuar.", None

        if user.get("is_blocked") and user.get("role") != "admin":
            return False, "blocked", "Tu cuenta se encuentra pausada.", None

        hwid_clean = (hwid or "").strip()[:64]
        if hwid_clean and user.get("role") != "admin":
            hwids = user.setdefault("hwids", [])
            max_dev = int(user.get("max_devices", 2))
            if hwid_clean not in hwids:
                if len(hwids) >= max_dev:
                    return (
                        False,
                        "device_limit",
                        f"Límite de {max_dev} computadora(s) alcanzado para esta cuenta.",
                        None,
                    )
                hwids.append(hwid_clean)

        self._refresh_user_cycles(user)

        # 1. Administrador o Plan Pro activo
        if user.get("role") == "admin" or user.get("plan") == "pro":
            used = int(user.get("docs_used_this_month", 0))
            limit = int(user.get("monthly_doc_limit", 100))
            if user.get("role") != "admin" and used >= limit:
                return (
                    False,
                    "quota_exceeded",
                    f"Alcanzaste el tope mensual incluido en tu plan ({limit} documentos). "
                    "Contactá al administrador para ampliar tu cupo.",
                    user,
                )
            return True, "pro", "OK", user

        # 2. Usuario Free: verificar si tiene disponible su ÚNICA prueba gratuita (por mail y por HWID)
        canon = user.get("canonical_email") or canonicalize_email(email)
        trial_left = int(user.get("free_trial_remaining", 0))
        email_used = canon in self.state.get("used_trial_emails", [])
        hwid_used = bool(hwid_clean and hwid_clean in self.state.get("used_trial_hwids", []))

        if trial_left > 0 and not email_used and not hwid_used:
            return True, "free_trial", "OK", user

        # Ya consumió su prueba gratuita única -> pedir activación Pro por Mercado Pago
        msg_pay = (
            "Ya utilizaste tu prueba gratuita de bienvenida.\n\n"
            "Activá tu Plan Pro abonando por Mercado Pago para desbloquear correcciones, "
            "instrucciones personalizadas ilimitadas y el modo Fuentes Locales estilo NotebookLM."
        )
        return False, "requires_pro", msg_pay, user

    def record_successful_correction(
        self,
        user: Dict[str, Any],
        auth_mode: str,
        hwid: str,
        modo: str,
        chars_total: int,
        ip: str = "",
    ) -> Dict[str, Any]:
        """Descuenta la prueba única (si era free_trial) o suma al contador mensual Pro y estima costo USD."""
        # Estimación realista con gemini-3.5-flash-lite (~4 chars/token, $0.30/1M in + $2.50/1M out)
        tokens_est = max(250, chars_total // 4)
        cost_est = round((tokens_est / 1_000_000) * 0.35 + (tokens_est / 1_000_000) * 2.50, 5)
        hwid_clean = (hwid or "").strip()[:64]
        canon = user.get("canonical_email") or canonicalize_email(user["email"])

        with self._lock:
            if auth_mode == "free_trial":
                user["free_trial_remaining"] = 0
                used_emails = self.state.setdefault("used_trial_emails", [])
                if canon not in used_emails:
                    used_emails.append(canon)
                if hwid_clean:
                    used_hwids = self.state.setdefault("used_trial_hwids", [])
                    if hwid_clean not in used_hwids:
                        used_hwids.append(hwid_clean)
            else:
                user["docs_used_this_month"] = int(user.get("docs_used_this_month", 0)) + 1

            user["total_docs_corrected"] = int(user.get("total_docs_corrected", 0)) + 1
            user["estimated_cost_usd"] = round(float(user.get("estimated_cost_usd", 0.0)) + cost_est, 5)
            self.state["stats"]["total_corrections"] = int(self.state["stats"].get("total_corrections", 0)) + 1
            self.state["stats"]["estimated_cost_usd"] = round(
                float(self.state["stats"].get("estimated_cost_usd", 0.0)) + cost_est, 5
            )

        etiqueta = "Prueba Gratuita Única" if auth_mode == "free_trial" else "Plan Pro"
        self.log_event(user["email"], f"Documento procesado ({modo} - {etiqueta})", ip=ip, cost_usd=cost_est)
        self.save_state(sync_drive=True)
        return self.build_public_user_profile(user, hwid_clean)

    # ------------------------------------------------------------------
    # Operaciones del Panel de Administrador (/admin)
    # ------------------------------------------------------------------
    def admin_update_user_plan(
        self,
        target_email: str,
        action: str,
        monthly_limit: Optional[int] = None,
    ) -> Tuple[bool, str]:
        u = self.state.get("users", {}).get(target_email.strip().lower())
        if not u:
            return False, "Usuario no encontrado."

        now = time.time()
        with self._lock:
            if action == "pro_30d":
                u["plan"] = "pro"
                base_ts = max(now, float(u.get("pro_expires_at") or 0))
                u["pro_expires_at"] = base_ts + 30 * 86400
                u["docs_used_this_month"] = 0
                u["month_period_start"] = now
                if monthly_limit:
                    u["monthly_doc_limit"] = max(1, monthly_limit)
                msg = f"Plan Pro activado por 30 días para {u['email']}."
            elif action == "pro_lifetime":
                u["plan"] = "pro"
                u["pro_expires_at"] = None
                if monthly_limit:
                    u["monthly_doc_limit"] = max(1, monthly_limit)
                msg = f"Plan Pro permanente activado para {u['email']}."
            elif action == "set_free":
                u["plan"] = "free"
                u["pro_expires_at"] = None
                msg = f"{u['email']} pasó a estado Gratuito."
            elif action == "grant_1_trial":
                u["free_trial_remaining"] = int(u.get("free_trial_remaining", 0)) + 1
                canon = u.get("canonical_email") or canonicalize_email(u["email"])
                if canon in self.state.get("used_trial_emails", []):
                    self.state["used_trial_emails"].remove(canon)
                for hw in u.get("hwids", []):
                    if hw in self.state.get("used_trial_hwids", []):
                        self.state["used_trial_hwids"].remove(hw)
                msg = f"Se habilitó +1 prueba gratuita para {u['email']}."
            elif action == "reset_hwid":
                u["hwids"] = []
                msg = f"Equipos vinculados (HWID) blanqueados para {u['email']}."
            elif action == "toggle_block":
                u["is_blocked"] = not bool(u.get("is_blocked", False))
                estado_txt = "pausada" if u["is_blocked"] else "reactivada"
                msg = f"Cuenta {u['email']} {estado_txt}."
            elif action == "force_verify_email":
                u["email_verified"] = True
                u["verified_at"] = now
                self.state.get("pending_otps", {}).pop(u["email"], None)
                msg = f"Correo marcado manualmente como verificado para {u['email']}."
            else:
                return False, "Acción desconocida."

        self.log_event("ADMIN", msg)
        self.save_state(sync_drive=True)
        return True, msg

    def admin_update_settings(self, updates: Dict[str, Any]) -> None:
        allowed_keys = {
            "gemini_api_key",
            "gemini_fallback_api_key",
            "google_bridge_webhook_url",
            "smtp_host",
            "smtp_port",
            "smtp_user",
            "smtp_app_password",
            "smtp_from_name",
            "brevo_api_key",
            "mp_alias",
            "mp_payment_link",
            "support_whatsapp",
            "pro_price_text",
        }
        with self._lock:
            s = self.state.setdefault("settings", {})
            for k, v in updates.items():
                if k in allowed_keys and v is not None:
                    val_str = str(v).strip()
                    # No sobrescribir claves secretas si el formulario envió máscara vacía/asteriscos
                    if k in ("gemini_api_key", "gemini_fallback_api_key", "smtp_app_password", "brevo_api_key"):
                        if not val_str or set(val_str) == {"*"}:
                            continue
                    s[k] = val_str
            if "default_monthly_doc_limit" in updates:
                try:
                    self.state["default_monthly_doc_limit"] = max(1, int(updates["default_monthly_doc_limit"]))
                except ValueError:
                    pass
        self.log_event("ADMIN", "Configuración comercial / correo / API actualizada")
        self.save_state(sync_drive=True)


server_manager = CommercialServerManager()
