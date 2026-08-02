from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import secrets
import smtplib
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, field_validator
from supabase import Client, create_client

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env.backend")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("campus-desk-password-reset")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required backend environment variable: {name}")
    return value


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_service_role_key: str
    otp_pepper: str
    frontend_origins: tuple[str, ...]
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from_email: str
    smtp_from_name: str
    smtp_use_tls: bool
    smtp_use_ssl: bool
    otp_expire_minutes: int
    otp_resend_cooldown_seconds: int
    otp_max_attempts: int
    otp_max_requests_per_hour: int
    otp_max_ip_requests_per_hour: int
    reset_token_expire_minutes: int
    password_min_length: int
    portfolio_url: str

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(
            origin.strip().rstrip("/")
            for origin in os.getenv(
                "FRONTEND_ORIGINS",
                "http://localhost:3000,http://localhost:5173,https://campusdesk.netlify.app",
            ).split(",")
            if origin.strip()
        )
        return cls(
            supabase_url=_required("SUPABASE_URL").rstrip("/"),
            supabase_service_role_key=_required("SUPABASE_SERVICE_ROLE_KEY"),
            otp_pepper=_required("OTP_PEPPER"),
            frontend_origins=origins,
            smtp_host=_required("SMTP_HOST"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME", "").strip(),
            smtp_password=os.getenv("SMTP_PASSWORD", ""),
            smtp_from_email=_required("SMTP_FROM_EMAIL"),
            smtp_from_name=os.getenv("SMTP_FROM_NAME", "Campus Desk").strip() or "Campus Desk",
            smtp_use_tls=_bool_env("SMTP_USE_TLS", True),
            smtp_use_ssl=_bool_env("SMTP_USE_SSL", False),
            otp_expire_minutes=max(3, int(os.getenv("OTP_EXPIRE_MINUTES", "10"))),
            otp_resend_cooldown_seconds=max(30, int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))),
            otp_max_attempts=max(3, int(os.getenv("OTP_MAX_ATTEMPTS", "5"))),
            otp_max_requests_per_hour=max(3, int(os.getenv("OTP_MAX_REQUESTS_PER_HOUR", "5"))),
            otp_max_ip_requests_per_hour=max(5, int(os.getenv("OTP_MAX_IP_REQUESTS_PER_HOUR", "20"))),
            reset_token_expire_minutes=max(5, int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", "10"))),
            password_min_length=max(8, int(os.getenv("PASSWORD_MIN_LENGTH", "8"))),
            portfolio_url=os.getenv("MW_TRADER_PORTFOLIO_URL", "https://mwtraderportfolio.netlify.app").strip(),
        )


settings = Settings.from_env()
supabase: Client = create_client(settings.supabase_url, settings.supabase_service_role_key)

app = FastAPI(
    title="Campus Desk Password Recovery API",
    version="1.0.0",
    docs_url="/docs" if _bool_env("ENABLE_API_DOCS", False) else None,
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.frontend_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
)


class EmailRequest(BaseModel):
    email: EmailStr


class VerifyCodeRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CompleteResetRequest(BaseModel):
    email: EmailStr
    reset_token: str = Field(min_length=32, max_length=512)
    new_password: str = Field(min_length=8, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("Password cannot begin or end with spaces.")
        if not any(character.isalpha() for character in value):
            raise ValueError("Password must include at least one letter.")
        if not any(character.isdigit() for character in value):
            raise ValueError("Password must include at least one number.")
        return value


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def digest(label: str, *parts: str) -> str:
    payload = ":".join((label, *parts)).encode("utf-8")
    return hmac.new(settings.otp_pepper.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def safe_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:500]


def rows(response: Any) -> list[dict[str, Any]]:
    data = getattr(response, "data", None)
    return data if isinstance(data, list) else []


def first_row(response: Any) -> dict[str, Any] | None:
    result = rows(response)
    return result[0] if result else None


def lookup_user(email: str) -> dict[str, Any] | None:
    response = (
        supabase.table("auth_user_directory")
        .select("user_id,email,role,school_id,is_active")
        .eq("email", email)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    return first_row(response)


def latest_request(email: str) -> dict[str, Any] | None:
    response = (
        supabase.table("password_reset_requests")
        .select("*")
        .eq("email", email)
        .order("requested_at", desc=True)
        .limit(1)
        .execute()
    )
    return first_row(response)


def active_verified_request(email: str) -> dict[str, Any] | None:
    response = (
        supabase.table("password_reset_requests")
        .select("*")
        .eq("email", email)
        .is_("consumed_at", "null")
        .order("requested_at", desc=True)
        .limit(10)
        .execute()
    )
    return next((row for row in rows(response) if row.get("verified_at")), None)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def audit(
    *,
    request_id: str | None,
    user: dict[str, Any] | None,
    email: str,
    event_type: str,
    request: Request,
    metadata: dict[str, Any] | None = None,
) -> None:
    payload = {
        "request_id": request_id,
        "user_id": user.get("user_id") if user else None,
        "school_id": user.get("school_id") if user else None,
        "role": user.get("role") if user else None,
        "email": email,
        "event_type": event_type,
        "request_ip_hash": digest("ip", client_ip(request)),
        "user_agent": safe_user_agent(request),
        "metadata": metadata or {},
    }
    try:
        supabase.table("password_reset_audit").insert(payload).execute()
    except Exception:
        logger.exception("Could not write password reset audit event %s", event_type)


def branded_email_html(code: str, expires_minutes: int) -> str:
    portfolio_url = html.escape(settings.portfolio_url, quote=True)
    return f"""<!doctype html>
<html lang="en">
  <body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f5f9;padding:32px 12px;">
      <tr><td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 18px 50px rgba(15,23,42,.10);">
          <tr><td style="background:#0f172a;padding:28px 32px;text-align:center;">
            <img src="cid:campus-desk-logo" width="72" height="72" alt="Campus Desk" style="display:block;margin:0 auto 14px;border:0;">
            <div style="font-size:28px;font-weight:800;letter-spacing:-1px;color:#ffffff;">Campus <span style="color:#38bdf8;">Desk</span></div>
            <div style="margin-top:8px;color:#cbd5e1;font-size:14px;">Secure account recovery</div>
          </td></tr>
          <tr><td style="padding:34px 32px;">
            <h1 style="margin:0;font-size:24px;line-height:1.3;">Your verification code</h1>
            <p style="margin:14px 0 0;color:#475569;font-size:15px;line-height:1.7;">Use this one-time code on the Campus Desk password-recovery page. It expires in {expires_minutes} minutes.</p>
            <div style="margin:28px 0;padding:20px;border:1px solid #bfdbfe;border-radius:18px;background:#eff6ff;text-align:center;font-size:36px;font-weight:800;letter-spacing:10px;color:#1d4ed8;">{code}</div>
            <p style="margin:0;color:#64748b;font-size:13px;line-height:1.7;">Do not share this code. Campus Desk support will never ask for your password or verification code.</p>
          </td></tr>
          <tr><td style="border-top:1px solid #e2e8f0;padding:20px 32px;text-align:center;color:#64748b;font-size:12px;">
            Designed and developed by <a href="{portfolio_url}" style="color:#2563eb;font-weight:700;text-decoration:none;">MW Trader</a>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>"""


def send_verification_email(recipient: str, code: str) -> None:
    message = EmailMessage()
    message["Subject"] = "Campus Desk password verification code"
    message["From"] = formataddr((settings.smtp_from_name, settings.smtp_from_email))
    message["To"] = recipient
    message.set_content(
        f"Your Campus Desk password verification code is {code}. "
        f"It expires in {settings.otp_expire_minutes} minutes."
    )
    message.add_alternative(branded_email_html(code, settings.otp_expire_minutes), subtype="html")

    logo_path = BASE_DIR / "assets" / "campus-desk-logo.png"
    if logo_path.exists():
        html_part = message.get_payload()[-1]
        html_part.add_related(
            logo_path.read_bytes(),
            maintype="image",
            subtype="png",
            cid="<campus-desk-logo>",
            filename="campus-desk-logo.png",
            disposition="inline",
        )

    smtp_class = smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP
    with smtp_class(settings.smtp_host, settings.smtp_port, timeout=25) as smtp:
        smtp.ehlo()
        if settings.smtp_use_tls and not settings.smtp_use_ssl:
            smtp.starttls()
            smtp.ehlo()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "campus-desk-password-recovery"}


@app.post("/api/password-reset/request")
def request_code(payload: EmailRequest, request: Request) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    ip_hash = digest("ip", client_ip(request))
    one_hour_ago = iso(utcnow() - timedelta(hours=1))
    ip_count_response = (
        supabase.table("password_reset_audit")
        .select("id", count="exact")
        .eq("request_ip_hash", ip_hash)
        .eq("event_type", "request_received")
        .gte("created_at", one_hour_ago)
        .execute()
    )
    ip_request_count = getattr(ip_count_response, "count", 0) or len(rows(ip_count_response))

    user = lookup_user(email)

    # Always return the same public wording so the endpoint does not reveal account existence.
    public_response = {
        "ok": True,
        "message": "If this email is registered, a Campus Desk verification code has been sent.",
        "expires_in_minutes": settings.otp_expire_minutes,
    }
    if ip_request_count >= settings.otp_max_ip_requests_per_hour:
        audit(request_id=None, user=user, email=email, event_type="ip_limit_reached", request=request)
        return public_response

    audit(request_id=None, user=user, email=email, event_type="request_received", request=request)

    if not user:
        audit(request_id=None, user=None, email=email, event_type="unknown_email_requested", request=request)
        time.sleep(0.35)
        return public_response

    now = utcnow()
    last = latest_request(email)
    if last:
        last_requested = parse_time(last.get("requested_at"))
        if last_requested and (now - last_requested).total_seconds() < settings.otp_resend_cooldown_seconds:
            audit(
                request_id=last.get("id"),
                user=user,
                email=email,
                event_type="request_throttled",
                request=request,
            )
            return public_response

    one_hour_ago = iso(now - timedelta(hours=1))
    count_response = (
        supabase.table("password_reset_requests")
        .select("id", count="exact")
        .eq("email", email)
        .gte("requested_at", one_hour_ago)
        .execute()
    )
    request_count = getattr(count_response, "count", 0) or len(rows(count_response))
    if request_count >= settings.otp_max_requests_per_hour:
        audit(request_id=None, user=user, email=email, event_type="hourly_limit_reached", request=request)
        return public_response

    request_id = str(uuid.uuid4())
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = now + timedelta(minutes=settings.otp_expire_minutes)

    # Invalidate any older unconsumed code before creating a new one.
    try:
        (
            supabase.table("password_reset_requests")
            .update({"consumed_at": iso(now), "delivery_status": "superseded"})
            .eq("email", email)
            .is_("consumed_at", "null")
            .execute()
        )
    except Exception:
        logger.exception("Could not supersede older password reset requests for %s", email)

    supabase.table("password_reset_requests").insert({
        "id": request_id,
        "user_id": user["user_id"],
        "school_id": user.get("school_id"),
        "role": user.get("role"),
        "email": email,
        "code_hash": digest("otp", request_id, email, code),
        "requested_at": iso(now),
        "expires_at": iso(expires_at),
        "attempts": 0,
        "delivery_status": "pending",
        "request_ip_hash": digest("ip", client_ip(request)),
        "user_agent": safe_user_agent(request),
    }).execute()

    try:
        send_verification_email(email, code)
        (
            supabase.table("password_reset_requests")
            .update({"delivery_status": "sent", "delivered_at": iso(utcnow())})
            .eq("id", request_id)
            .execute()
        )
        audit(request_id=request_id, user=user, email=email, event_type="code_sent", request=request)
    except Exception as exc:
        logger.exception("SMTP delivery failed for password reset request %s", request_id)
        (
            supabase.table("password_reset_requests")
            .update({"delivery_status": "failed", "delivery_error": str(exc)[:500]})
            .eq("id", request_id)
            .execute()
        )
        audit(
            request_id=request_id,
            user=user,
            email=email,
            event_type="email_delivery_failed",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The verification email could not be delivered. Check the backend SMTP configuration.",
        ) from exc

    return public_response


@app.post("/api/password-reset/verify")
def verify_code(payload: VerifyCodeRequest, request: Request) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    record = latest_request(email)
    if not record or record.get("consumed_at"):
        raise HTTPException(status_code=400, detail="The verification code is invalid or expired.")

    user = lookup_user(email)
    request_id = str(record["id"])
    expires_at = parse_time(record.get("expires_at"))
    attempts = int(record.get("attempts") or 0)

    if not expires_at or utcnow() >= expires_at:
        audit(request_id=request_id, user=user, email=email, event_type="expired_code_submitted", request=request)
        raise HTTPException(status_code=400, detail="The verification code has expired. Request a new code.")
    if attempts >= settings.otp_max_attempts:
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Request a new code.")

    expected = digest("otp", request_id, email, payload.code)
    if not hmac.compare_digest(expected, str(record.get("code_hash") or "")):
        attempts += 1
        (
            supabase.table("password_reset_requests")
            .update({"attempts": attempts, "last_attempt_at": iso(utcnow())})
            .eq("id", request_id)
            .execute()
        )
        audit(
            request_id=request_id,
            user=user,
            email=email,
            event_type="invalid_code",
            request=request,
            metadata={"attempt": attempts},
        )
        remaining = max(0, settings.otp_max_attempts - attempts)
        raise HTTPException(status_code=400, detail=f"Incorrect verification code. {remaining} attempt(s) remaining.")

    reset_token = secrets.token_urlsafe(48)
    verified_at = utcnow()
    token_expires_at = verified_at + timedelta(minutes=settings.reset_token_expire_minutes)
    (
        supabase.table("password_reset_requests")
        .update({
            "verified_at": iso(verified_at),
            "reset_token_hash": digest("reset", request_id, email, reset_token),
            "reset_token_expires_at": iso(token_expires_at),
            "last_attempt_at": iso(verified_at),
        })
        .eq("id", request_id)
        .execute()
    )
    audit(request_id=request_id, user=user, email=email, event_type="code_verified", request=request)
    return {
        "ok": True,
        "reset_token": reset_token,
        "expires_in_minutes": settings.reset_token_expire_minutes,
    }


@app.post("/api/password-reset/complete")
def complete_reset(payload: CompleteResetRequest, request: Request) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    if len(payload.new_password) < settings.password_min_length:
        raise HTTPException(
            status_code=400,
            detail=f"Your new password must contain at least {settings.password_min_length} characters.",
        )

    record = active_verified_request(email)
    if not record:
        raise HTTPException(status_code=400, detail="The verified password-reset session is invalid or expired.")

    request_id = str(record["id"])
    token_expires_at = parse_time(record.get("reset_token_expires_at"))
    if not token_expires_at or utcnow() >= token_expires_at:
        raise HTTPException(status_code=400, detail="The password-reset session has expired. Start again.")

    expected = digest("reset", request_id, email, payload.reset_token)
    if not hmac.compare_digest(expected, str(record.get("reset_token_hash") or "")):
        audit(request_id=request_id, user=lookup_user(email), email=email, event_type="invalid_reset_token", request=request)
        raise HTTPException(status_code=400, detail="The password-reset session is invalid. Start again.")

    user = lookup_user(email)
    if not user or str(user.get("user_id")) != str(record.get("user_id")):
        raise HTTPException(status_code=400, detail="The account could not be verified.")

    processing_at = utcnow()
    processing_lock = digest("processing", request_id, secrets.token_urlsafe(24))
    (
        supabase.table("password_reset_requests")
        .update({"processing_at": iso(processing_at), "processing_lock": processing_lock})
        .eq("id", request_id)
        .is_("consumed_at", "null")
        .is_("processing_at", "null")
        .execute()
    )
    lock_check = (
        supabase.table("password_reset_requests")
        .select("processing_lock")
        .eq("id", request_id)
        .limit(1)
        .execute()
    )
    if (first_row(lock_check) or {}).get("processing_lock") != processing_lock:
        raise HTTPException(status_code=409, detail="This password-reset session is already being processed or has been used.")

    try:
        supabase.auth.admin.update_user_by_id(
            str(user["user_id"]),
            {"password": payload.new_password},
        )
    except Exception as exc:
        logger.exception("Supabase Auth password update failed for request %s", request_id)
        try:
            (
                supabase.table("password_reset_requests")
                .update({"processing_at": None, "processing_lock": None})
                .eq("id", request_id)
                .eq("processing_lock", processing_lock)
                .execute()
            )
        except Exception:
            logger.exception("Could not release failed password-reset processing lock")
        audit(request_id=request_id, user=user, email=email, event_type="auth_update_failed", request=request)
        raise HTTPException(status_code=502, detail="The password could not be updated in Supabase Auth.") from exc

    completed_at = utcnow()
    (
        supabase.table("password_reset_requests")
        .update({"consumed_at": iso(completed_at), "completed_at": iso(completed_at), "processing_at": None, "processing_lock": None})
        .eq("id", request_id)
        .eq("processing_lock", processing_lock)
        .execute()
    )

    # Store only reset metadata. Never store or display the plaintext password.
    try:
        profile_response = (
            supabase.table("profiles")
            .select("password_reset_count")
            .eq("id", user["user_id"])
            .limit(1)
            .execute()
        )
        profile_row = first_row(profile_response) or {}
        (
            supabase.table("profiles")
            .update({
                "last_password_reset_at": iso(completed_at),
                "password_reset_count": int(profile_row.get("password_reset_count") or 0) + 1,
            })
            .eq("id", user["user_id"])
            .execute()
        )
    except Exception:
        # The audit entry and Supabase Auth update remain authoritative even if optional metadata fails.
        logger.exception("Could not update profile password-reset metadata")

    if user.get("school_id"):
        try:
            (
                supabase.table("schools")
                .update({"last_password_reset_at": iso(completed_at)})
                .eq("id", user["school_id"])
                .execute()
            )
        except Exception:
            logger.exception("Could not update institute password-reset timestamp")

    audit(request_id=request_id, user=user, email=email, event_type="password_updated", request=request)
    return {
        "ok": True,
        "message": "Your Campus Desk password has been updated successfully. You can now sign in.",
    }


class RegisterOTPRequest(BaseModel):
    email: EmailStr

class RegisterOTPVerify(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")

@app.post("/api/register/request-otp")
def register_request_otp(payload: RegisterOTPRequest, request: Request) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    now = utcnow()
    
    # Rate limit check by email
    one_hour_ago = iso(now - timedelta(hours=1))
    count_response = supabase.table("registration_otps").select("email", count="exact").eq("email", email).gte("requested_at", one_hour_ago).execute()
    request_count = getattr(count_response, "count", 0) or len(rows(count_response))
    if request_count >= settings.otp_max_requests_per_hour:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = now + timedelta(minutes=settings.otp_expire_minutes)
    
    # Upsert the OTP request
    supabase.table("registration_otps").upsert({
        "email": email,
        "code_hash": digest("register-otp", email, code),
        "requested_at": iso(now),
        "expires_at": iso(expires_at),
        "attempts": 0,
        "verified": False,
        "verified_at": None,
        "request_ip_hash": digest("ip", client_ip(request)),
        "user_agent": safe_user_agent(request),
    }).execute()

    try:
        send_verification_email(email, code)
    except Exception as exc:
        logger.exception("SMTP delivery failed for registration OTP %s", email)
        raise HTTPException(
            status_code=502,
            detail="The verification email could not be delivered. Check the backend SMTP configuration.",
        ) from exc

    return {
        "ok": True,
        "message": f"Verification code sent to {email}. It expires in {settings.otp_expire_minutes} minutes.",
        "expires_in_minutes": settings.otp_expire_minutes,
    }

@app.post("/api/register/verify-otp")
def register_verify_otp(payload: RegisterOTPVerify, request: Request) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    response = supabase.table("registration_otps").select("*").eq("email", email).limit(1).execute()
    record = first_row(response)
    
    if not record:
        raise HTTPException(status_code=400, detail="No verification code was requested for this email.")
        
    if record.get("verified"):
        return {"ok": True, "message": "Email is already verified."}

    expires_at = parse_time(record.get("expires_at"))
    attempts = int(record.get("attempts") or 0)

    if not expires_at or utcnow() >= expires_at:
        raise HTTPException(status_code=400, detail="The verification code has expired. Request a new code.")
        
    if attempts >= settings.otp_max_attempts:
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Request a new code.")

    expected = digest("register-otp", email, payload.code)
    if not hmac.compare_digest(expected, str(record.get("code_hash") or "")):
        attempts += 1
        supabase.table("registration_otps").update({"attempts": attempts}).eq("email", email).execute()
        remaining = max(0, settings.otp_max_attempts - attempts)
        raise HTTPException(status_code=400, detail=f"Incorrect verification code. {remaining} attempt(s) remaining.")

    verified_at = utcnow()
    supabase.table("registration_otps").update({
        "verified": True,
        "verified_at": iso(verified_at),
    }).eq("email", email).execute()
    
    return {
        "ok": True,
        "message": "Email verified successfully.",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
