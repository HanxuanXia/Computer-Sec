<?php
/**
 * Security Configuration File
 * Contains API keys and configuration for advanced security features
 * 
 * IMPORTANT: Keep this file secure and never commit real keys to version control!
 */

// ============================================================================
// GOOGLE reCAPTCHA v2 Configuration (CHECKBOX VERSION)
// ============================================================================
// Get your keys from: https://www.google.com/recaptcha/admin
// Choose reCAPTCHA v2 → "I'm not a robot" Checkbox
// 
// NOTE: reCAPTCHA v2 shows a CHECKBOX that users must click!
// This is the visible "I'm not a robot" challenge.
// 
// Test keys below work for localhost development.
// For production, register your domain at: https://www.google.com/recaptcha/admin
// ============================================================================

// Enable/Disable reCAPTCHA
define('RECAPTCHA_ENABLED', true); // ✅ ENABLED

// reCAPTCHA Development Mode (for localhost testing)
// When true, reCAPTCHA verification will always pass in development
define('RECAPTCHA_DEV_MODE', true); // ✅ Set to true for localhost testing

// reCAPTCHA Version: 'v2' or 'v3'
define('RECAPTCHA_VERSION', 'v2'); // v2 = Checkbox, v3 = Invisible

// Real Google reCAPTCHA v2 keys (PRODUCTION)
// Site Key (visible on client-side): 6LdfeiQsAAAAAKlnBsLN1HccnQolZcnVBbG0Q4Jj
// Secret Key (server-side only): 6LdfeiQsAAAAAHiVfIYRauANuaAedec-S9YYgr07
define('RECAPTCHA_SITE_KEY', '6LdfeiQsAAAAAKlnBsLN1HccnQolZcnVBbG0Q4Jj'); 
define('RECAPTCHA_SECRET_KEY', '6LdfeiQsAAAAAHiVfIYRauANuaAedec-S9YYgr07'); 

// Score threshold (only for v3 - ignored in v2)
// Recommended: 0.5 for general use, 0.7 for high security
define('RECAPTCHA_SCORE_THRESHOLD', 0.5);

// Actions to protect
define('RECAPTCHA_ACTIONS', [
    'login' => true,
    'register' => true,
    'forgot_password' => true,
    'submit_request' => false  // Optional: protect evaluation requests
]);

// ============================================================================
// 2FA (Two-Factor Authentication) Configuration
// ============================================================================

define('TWO_FACTOR_ENABLED', true); // ✅ ENABLED - Users can enable 2FA for extra security
define('TWO_FACTOR_ISSUER', 'Lovejoy Antiques'); // Appears in Google Authenticator
define('TWO_FACTOR_BACKUP_CODES_COUNT', 10); // Number of backup codes to generate

// 2FA Enforcement Options
define('TWO_FACTOR_MANDATORY_FOR_ADMINS', true); // ✅ Admins must use 2FA
define('TWO_FACTOR_MANDATORY_FOR_ALL', true);    // ✅ 改为 true = 所有用户强制使用 2FA
define('TWO_FACTOR_GRACE_PERIOD_DAYS', 7);       // Days before 2FA becomes mandatory (if enforced)

// ============================================================================
// Email Verification Configuration
// ============================================================================

define('EMAIL_VERIFICATION_ENABLED', false); // ❌ DISABLED - No email verification required
define('EMAIL_VERIFICATION_REQUIRED', false); // ❌ DISABLED - Allow login without verification
define('EMAIL_VERIFICATION_TOKEN_EXPIRY', 24 * 3600); // 24 hours in seconds

// Allow login before verification (but with limited access)
define('ALLOW_UNVERIFIED_LOGIN', true); // Allow login without email verification

// ============================================================================
// Email Configuration (SMTP)
// ============================================================================
// Required for sending verification emails and 2FA recovery codes
// ============================================================================

// 📧 Email Mode
// - 'demo': Show links on page (for local testing, no email sent)
// - 'smtp': Send real emails via SMTP (requires configuration below)
// - 'hybrid': Try SMTP, fallback to demo mode if fails
define('EMAIL_MODE', 'smtp'); // ⭐ Changed to 'smtp' for real email sending

define('SMTP_ENABLED', true); // Set to true when using 'smtp' or 'hybrid' mode

// SMTP Server Settings
define('SMTP_HOST', 'smtp.gmail.com'); // e.g., smtp.gmail.com, smtp.office365.com
define('SMTP_PORT', 587); // 587 for TLS, 465 for SSL
define('SMTP_ENCRYPTION', 'tls'); // 'tls' or 'ssl'
define('SMTP_USERNAME', 'hxia679@gmail.com'); // Your SMTP username
define('SMTP_PASSWORD', 'cflp yxng dxdj xmli'); // Your SMTP password or app password
define('SMTP_FROM_EMAIL', 'hxia679@gmail.com'); // From email address
define('SMTP_FROM_NAME', 'Lovejoy Antiques'); // From name

// ============================================================================
// Application URL Configuration
// ============================================================================
// Used for generating verification links and QR codes
// ============================================================================

// Auto-detect base URL (works for most cases)
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)) ? "https://" : "http://";
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$script_dir = dirname($_SERVER['SCRIPT_NAME'] ?? '');

define('BASE_URL', $protocol . $host . $script_dir);

// Or manually set it:
// define('BASE_URL', 'http://localhost/Compsec/lovejoy_secure_app');

// ============================================================================
// Security Settings Summary
// ============================================================================
/*
FEATURE STATUS:
- reCAPTCHA v3: <?php echo RECAPTCHA_ENABLED ? 'ENABLED' : 'DISABLED'; ?>

- Two-Factor Auth: <?php echo TWO_FACTOR_ENABLED ? 'ENABLED' : 'DISABLED'; ?>

- Email Verification: <?php echo EMAIL_VERIFICATION_ENABLED ? 'ENABLED' : 'DISABLED'; ?>


SETUP INSTRUCTIONS:

1. reCAPTCHA v3:
   - Get keys from: https://www.google.com/recaptcha/admin
   - Replace RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY above
   - Choose reCAPTCHA v3 (not v2)

2. 2FA (Google Authenticator):
   - Install library: composer require pragmarx/google2fa
   - Or use the included 2fa.php (no composer needed)

3. Email Verification:
   - Configure SMTP settings above
   - For Gmail: Use App Password (not regular password)
   - Enable "Less secure apps" or create app-specific password

4. Testing:
   - Use test keys provided above for initial testing
   - Replace with production keys before going live
*/
?>
