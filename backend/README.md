# Campus Desk Python Password-Recovery Backend

This backend sends branded six-digit verification codes and securely updates the user's real Supabase Auth password after the code is verified.

## Security model

- The Supabase service-role key stays only in `backend/.env.backend` on the VPS.
- The browser never receives the service-role key or SMTP password.
- Verification codes and reset tokens are stored only as HMAC-SHA256 hashes.
- Codes expire, are single-use, have retry limits, resend cooldowns, per-email hourly limits and per-IP hourly limits.
- Passwords are updated only in Supabase Auth. Plaintext passwords are never stored in `schools`, `profiles`, audit logs, exports, or the Admin Panel.
- The Admin Panel can show only the last-reset timestamp/audit status.

## 1. Run the SQL migration

Open Supabase Dashboard → SQL Editor and run:

`backend/sql/20260730_password_recovery_backend.sql`

Run the existing platform migrations first if they are still pending.

## 2. Configure the backend

Copy:

`backend/.env.backend.example` → `backend/.env.backend`

Fill the Supabase service-role key, SMTP credentials, a long random `OTP_PEPPER`, and your exact Netlify frontend URL in `FRONTEND_ORIGINS`.

Generate the pepper with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## 3. Start on Windows VPS

Run either:

- `backend/run_backend.bat`
- `backend/run_backend.ps1`

The API runs on port `8000` by default.

## 4. Use HTTPS in production

The Netlify website is HTTPS, so the production backend URL must also use HTTPS. Put Nginx, Caddy, IIS reverse proxy, Cloudflare Tunnel, or another TLS proxy in front of port 8000.

Example production API URL:

`https://api.yourdomain.com`

## 5. Configure Netlify frontend

Add this Netlify environment variable:

`VITE_PASSWORD_RESET_API_URL=https://api.yourdomain.com`

Then redeploy the frontend.

## 6. Test

1. Open `/forgot-password`.
2. Enter a registered institute email.
3. Confirm the branded Campus Desk email arrives.
4. Enter the six-digit code.
5. Set a new password.
6. Sign in using the new password.
7. Confirm `password_reset_audit` has the expected events and `schools.last_password_reset_at` was updated.

The API health endpoint is:

`GET /health`
