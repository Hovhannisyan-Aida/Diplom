import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from app.core.config import settings

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, token: str):
    verification_url = (
        f"{settings.BACKEND_URL}/api/v1/auth/verify-email?token={token}"
    )

    html = f"""
    <html>
    <body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 0;">
        <tr><td align="center">
          <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

            <!-- Header -->
            <tr>
              <td style="background:linear-gradient(135deg,#667eea,#764ba2);padding:36px 40px;text-align:center;">
                <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:800;letter-spacing:-0.5px;">
                  🛡️ Vulnerability Scanner
                </h1>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:40px;">
                <h2 style="margin:0 0 16px;color:#1e293b;font-size:20px;">Verify your email address</h2>
                <p style="margin:0 0 24px;color:#64748b;font-size:15px;line-height:1.7;">
                  Thanks for signing up! Click the button below to verify your email address
                  and activate your account. This link expires in <strong>24 hours</strong>.
                </p>

                <div style="text-align:center;margin:32px 0;">
                  <a href="{verification_url}"
                     style="display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);
                            color:#ffffff;padding:16px 40px;border-radius:8px;
                            text-decoration:none;font-size:16px;font-weight:700;
                            letter-spacing:0.3px;">
                    Verify My Email
                  </a>
                </div>

                <p style="margin:24px 0 0;color:#94a3b8;font-size:13px;line-height:1.6;">
                  If the button doesn't work, copy and paste this link into your browser:<br>
                  <a href="{verification_url}" style="color:#667eea;word-break:break-all;">{verification_url}</a>
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background:#f8fafc;padding:24px 40px;border-top:1px solid #e2e8f0;text-align:center;">
                <p style="margin:0;color:#94a3b8;font-size:12px;">
                  If you didn't create an account, you can safely ignore this email.<br>
                  © 2025 Vulnerability Scanner
                </p>
              </td>
            </tr>

          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Verify your Vulnerability Scanner account'
    msg['From'] = f"Vulnerability Scanner <{settings.SMTP_FROM}>"
    msg['To'] = to_email
    msg.attach(MIMEText(html, 'html'))

    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.warning(f"SMTP not configured. Verification URL: {verification_url}")
        print(f"\n[EMAIL NOT SENT] Verification URL: {verification_url}\n", flush=True)
        return

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, to_email, msg.as_string())
        logger.info(f"Verification email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {to_email}: {e}")
        print(f"\n[EMAIL FAILED] Verification URL: {verification_url}\n", flush=True)
