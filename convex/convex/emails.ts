/**
 * Transactional email sending via Resend.
 *
 * All emails are sent from noreply@usesicario.xyz.
 * Set RESEND_API_KEY in your Convex environment variables.
 *
 * Free tier: 3,000 emails/month, no credit card required.
 * Sign up at https://resend.com and add your domain.
 */

import { Resend } from "resend";

function getResend(): Resend {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    throw new Error(
      "RESEND_API_KEY is not set. Add it via `npx convex env set RESEND_API_KEY re_...`"
    );
  }
  return new Resend(key);
}

const FROM = "Emmanuel from Sicario <noreply@usesicario.xyz>";

// ── Shared design tokens ──────────────────────────────────────────────────────

const colors = {
  bg: "#0a0a0a",
  surface: "#111111",
  border: "#1f1f1f",
  borderSubtle: "#181818",
  accent: "#ADFF2F",
  accentDark: "#8fd400",
  textPrimary: "#f4f4f5",
  textSecondary: "#a1a1aa",
  textMuted: "#52525b",
  codeText: "#ADFF2F",
  codeBg: "#0a0a0a",
};

// ── Logo SVG (inline, email-safe) ─────────────────────────────────────────────
// The Sicario logo mark: a filled circle with a diagonal slash — rendered as
// a table-based layout so it works in Outlook and Gmail without SVG support.

function logoHtml(): string {
  return `
    <table cellpadding="0" cellspacing="0" border="0" role="presentation">
      <tr>
        <td style="vertical-align:middle;padding-right:10px">
          <!--[if !mso]><!-->
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:block">
            <circle cx="14" cy="14" r="14" fill="${colors.accent}"/>
            <line x1="20" y1="7" x2="8" y2="21" stroke="#000000" stroke-width="3" stroke-linecap="round"/>
          </svg>
          <!--<![endif]-->
          <!--[if mso]>
          <v:oval xmlns:v="urn:schemas-microsoft-com:vml" style="width:28px;height:28px" fillcolor="${colors.accent}" stroked="f">
          </v:oval>
          <![endif]-->
        </td>
        <td style="vertical-align:middle">
          <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:18px;font-weight:800;color:#ffffff;letter-spacing:0.08em;text-transform:uppercase">SICARIO</span>
        </td>
      </tr>
    </table>`;
}

// ── Shared email shell ────────────────────────────────────────────────────────

function emailShell(content: string, previewText: string): string {
  return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="x-apple-disable-message-reformatting">
  <title>Sicario</title>
  <!--[if mso]>
  <noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript>
  <![endif]-->
  <style>
    body, table, td, a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
    table, td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
    img { -ms-interpolation-mode:bicubic; border:0; outline:none; text-decoration:none; }
    body { margin:0; padding:0; background-color:${colors.bg}; }
    a { color:${colors.accent}; }
    @media only screen and (max-width:600px) {
      .email-container { width:100% !important; }
      .stack-column { display:block !important; width:100% !important; }
      .mobile-padding { padding:24px 20px !important; }
      .mobile-btn { width:100% !important; text-align:center !important; }
    }
  </style>
</head>
<body style="margin:0;padding:0;background-color:${colors.bg};word-spacing:normal">
  <!-- Preview text (hidden) -->
  <div style="display:none;font-size:1px;color:${colors.bg};line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden">${previewText}&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌</div>

  <!-- Outer wrapper -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${colors.bg}">
    <tr>
      <td align="center" style="padding:40px 16px">

        <!-- Email container -->
        <table class="email-container" role="presentation" cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%">

          <!-- ── HEADER ── -->
          <tr>
            <td style="background-color:${colors.surface};border:1px solid ${colors.border};border-bottom:none;border-radius:12px 12px 0 0;padding:28px 40px 24px">
              ${logoHtml()}
            </td>
          </tr>

          <!-- ── DIVIDER ── -->
          <tr>
            <td style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border};padding:0 40px">
              <div style="height:1px;background-color:${colors.borderSubtle};font-size:0;line-height:0">&nbsp;</div>
            </td>
          </tr>

          <!-- ── BODY ── -->
          <tr>
            <td class="mobile-padding" style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border};padding:36px 40px">
              ${content}
            </td>
          </tr>

          <!-- ── FOOTER ── -->
          <tr>
            <td style="background-color:${colors.surface};border:1px solid ${colors.border};border-top:1px solid ${colors.borderSubtle};border-radius:0 0 12px 12px;padding:20px 40px">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                <tr>
                  <td>
                    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
                      You're receiving this email because you have a Sicario account.
                      <br>
                      <a href="https://usesicario.xyz" style="color:${colors.textMuted};text-decoration:underline">usesicario.xyz</a>
                      &nbsp;·&nbsp;
                      <a href="https://usesicario.xyz/privacy" style="color:${colors.textMuted};text-decoration:underline">Privacy Policy</a>
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
        <!-- /Email container -->

      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ── Welcome email ─────────────────────────────────────────────────────────────

export async function sendWelcomeEmail(to: string, name?: string): Promise<void> {
  const resend = getResend();
  const displayName = name ?? to.split("@")[0];

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Welcome, ${displayName}
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Your Sicario account is ready. Scan your codebase for vulnerabilities, publish results to the cloud dashboard, and fix them with AI-powered auto-remediation — all without your source code ever leaving your machine.
    </p>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 32px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Go to Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 28px;font-size:0;line-height:0">&nbsp;</div>

    <!-- Quick start -->
    <p style="margin:0 0 12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;color:${colors.textMuted};letter-spacing:0.06em;text-transform:uppercase">
      Get started in 30 seconds
    </p>

    <!-- Code block 1 -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">curl -fsSL https://usesicario.xyz/install.sh | sh</code>
        </td>
      </tr>
    </table>

    <!-- Code block 2 -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">sicario scan . --publish</code>
        </td>
      </tr>
    </table>

    <!-- Feature pills -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">500+ rules</span>
        </td>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">AI auto-fix</span>
        </td>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">Zero exfiltration</span>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Welcome to Sicario",
    html: emailShell(content, `Your Sicario account is ready, ${displayName}.`),
  });
}

// ── Password reset OTP email ──────────────────────────────────────────────────

export async function sendPasswordResetEmail(
  to: string,
  otp: string
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Reset your password
    </h1>
    <p style="margin:0 0 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      We received a request to reset the password for your Sicario account. Use the code below — it expires in <strong style="color:${colors.textPrimary}">1 hour</strong>.
    </p>

    <!-- OTP block -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td align="center" style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:10px;padding:28px 20px">
          <p style="margin:0 0 6px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:${colors.textMuted}">
            Your reset code
          </p>
          <span style="font-family:'Courier New',Courier,monospace;font-size:38px;font-weight:700;letter-spacing:0.2em;color:${colors.accent}">${otp}</span>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 24px;font-size:0;line-height:0">&nbsp;</div>

    <!-- Security notice -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 4px">
      <tr>
        <td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8aad3a">
            <strong style="color:${colors.accent}">Didn't request this?</strong>
            &nbsp;You can safely ignore this email. Your password will not change and this code will expire automatically.
          </p>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Reset your Sicario password",
    html: emailShell(content, "Your password reset code is inside."),
  });
}
