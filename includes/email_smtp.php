<?php
/**
 * SMTP Email Implementation using PHPMailer
 * Sends emails via Gmail SMTP for password reset and verification
 */

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/security_config.php';

/**
 * Send email using Gmail SMTP
 * 
 * @param string $to Recipient email
 * @param string $name Recipient name
 * @param string $token Verification/Reset token
 * @param string $type Type: 'registration', 'password_reset', or '2fa_code'
 * @param array $extraData Additional data (e.g., code for 2FA)
 * @return array ['success' => bool, 'message' => string, 'debug' => string]
 */
function sendEmailViaSMTP($to, $name, $token, $type = 'registration', $extraData = []) {
    $mail = new PHPMailer(true);
    
    try {
        // Server settings
        if (defined('SMTP_DEBUG') && SMTP_DEBUG) {
            $mail->SMTPDebug = SMTP::DEBUG_SERVER; // Enable verbose debug output
        } else {
            $mail->SMTPDebug = 0; // Disable debug output in production
        }
        
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION === 'ssl' ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;
        $mail->CharSet    = 'UTF-8';
        
        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($to, $name);
        $mail->addReplyTo(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        
        // Content based on type
        $mail->isHTML(true);
        
        if ($type === 'registration') {
            $mail->Subject = 'Verify Your Email - Lovejoy\'s Antiques';
            $mail->Body = getRegistrationEmailHTML($name, $token);
            $mail->AltBody = getRegistrationEmailText($name, $token);
            
        } else if ($type === 'password_reset') {
            $mail->Subject = 'Reset Your Password - Lovejoy\'s Antiques';
            $mail->Body = getPasswordResetEmailHTML($name, $token);
            $mail->AltBody = getPasswordResetEmailText($name, $token);
            
        } else if ($type === '2fa_code') {
            $code = $extraData['code'] ?? '000000';
            $mail->Subject = 'Your 2FA Code - Lovejoy\'s Antiques';
            $mail->Body = get2FACodeEmailHTML($name, $code);
            $mail->AltBody = get2FACodeEmailText($name, $code);
        }
        
        // Send email
        $mail->send();
        
        logSecurityEvent('EMAIL_SENT_SMTP', "Email sent to: $to (Type: $type)");
        
        return [
            'success' => true,
            'message' => 'Email sent successfully',
            'debug' => ''
        ];
        
    } catch (Exception $e) {
        error_log("SMTP Email Error: {$mail->ErrorInfo}");
        logSecurityEvent('EMAIL_FAILED_SMTP', "Failed to send email to: $to - Error: {$mail->ErrorInfo}");
        
        return [
            'success' => false,
            'message' => 'Failed to send email',
            'debug' => $mail->ErrorInfo
        ];
    }
}

/**
 * Get HTML email for registration verification
 */
function getRegistrationEmailHTML($name, $token) {
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/";
    $verify_link = $base_url . "verify_email.php?token=" . $token;
    
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 28px; }
            .header .icon { font-size: 48px; margin-bottom: 10px; }
            .content { padding: 30px; }
            .content h2 { color: #333; margin-top: 0; }
            .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
            .button:hover { background: #5568d3; }
            .link-box { background: #f8f9fa; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; margin: 20px 0; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
            .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <div class='icon'>🏺</div>
                <h1>Lovejoy's Antiques</h1>
                <p>Welcome to our antique evaluation service</p>
            </div>
            <div class='content'>
                <h2>Hello " . htmlspecialchars($name) . "!</h2>
                <p>Thank you for registering with Lovejoy's Antiques. Please verify your email address to activate your account.</p>
                
                <p style='text-align: center;'>
                    <a href='" . $verify_link . "' class='button'>✓ Verify Email Address</a>
                </p>
                
                <p>Or copy and paste this link into your browser:</p>
                <div class='link-box'>" . $verify_link . "</div>
                
                <div class='warning'>
                    <strong>⏰ Important:</strong> This verification link will expire in 24 hours.
                </div>
                
                <p>If you didn't create this account, please ignore this email or contact us if you have concerns.</p>
            </div>
            <div class='footer'>
                <p><strong>© 2025 Lovejoy's Antiques</strong></p>
                <p>This is an automated email. Please do not reply.</p>
                <p style='margin-top: 10px; font-size: 11px;'>🔒 Sent via secure email server</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

/**
 * Get plain text email for registration (fallback)
 */
function getRegistrationEmailText($name, $token) {
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/";
    $verify_link = $base_url . "verify_email.php?token=" . $token;
    
    return "
LOVEJOY'S ANTIQUES
Welcome to our antique evaluation service

Hello " . $name . "!

Thank you for registering with Lovejoy's Antiques. Please verify your email address to activate your account.

Verify your email by clicking this link:
" . $verify_link . "

IMPORTANT: This verification link will expire in 24 hours.

If you didn't create this account, please ignore this email.

© 2025 Lovejoy's Antiques
This is an automated email. Please do not reply.
    ";
}

/**
 * Get HTML email for password reset
 */
function getPasswordResetEmailHTML($name, $token) {
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/";
    $reset_link = $base_url . "forgot_password.php?step=reset&token=" . $token;
    
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 28px; }
            .header .icon { font-size: 48px; margin-bottom: 10px; }
            .content { padding: 30px; }
            .content h2 { color: #333; margin-top: 0; }
            .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
            .button:hover { background: #5568d3; }
            .link-box { background: #f8f9fa; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; margin: 20px 0; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
            .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
            .security-tips { background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0; }
            .security-tips ul { margin: 10px 0; padding-left: 20px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <div class='icon'>🔐</div>
                <h1>Password Reset Request</h1>
            </div>
            <div class='content'>
                <h2>Hello " . htmlspecialchars($name) . "!</h2>
                <p>We received a request to reset your password for your Lovejoy's Antiques account.</p>
                
                <p style='text-align: center;'>
                    <a href='" . $reset_link . "' class='button'>🔑 Reset Password</a>
                </p>
                
                <p>Or copy and paste this link into your browser:</p>
                <div class='link-box'>" . $reset_link . "</div>
                
                <div class='warning'>
                    <strong>⚠️ Security Notice:</strong>
                    <ul style='margin: 10px 0; padding-left: 20px;'>
                        <li>This link will expire in <strong>1 hour</strong></li>
                        <li>You can only use this link <strong>once</strong></li>
                        <li>If you didn't request this, please <strong>ignore this email</strong></li>
                    </ul>
                </div>
                
                <div class='security-tips'>
                    <strong>🛡️ Security Recommendations:</strong>
                    <ul>
                        <li>Use a strong, unique password (minimum 8 characters)</li>
                        <li>Include uppercase, lowercase, numbers, and special characters</li>
                        <li>Don't share your password with anyone</li>
                        <li>Enable two-factor authentication for extra security</li>
                    </ul>
                </div>
                
                <p style='color: #666; font-size: 14px; margin-top: 30px;'>
                    If you didn't request a password reset, someone may be trying to access your account. 
                    We recommend changing your password immediately or contacting support.
                </p>
            </div>
            <div class='footer'>
                <p><strong>© 2025 Lovejoy's Antiques</strong></p>
                <p>This is an automated email. Please do not reply.</p>
                <p style='margin-top: 10px; font-size: 11px;'>🔒 Sent via secure email server</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

/**
 * Get plain text email for password reset (fallback)
 */
function getPasswordResetEmailText($name, $token) {
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/";
    $reset_link = $base_url . "forgot_password.php?step=reset&token=" . $token;
    
    return "
LOVEJOY'S ANTIQUES
Password Reset Request

Hello " . $name . "!

We received a request to reset your password for your Lovejoy's Antiques account.

Reset your password by clicking this link:
" . $reset_link . "

SECURITY NOTICE:
- This link will expire in 1 hour
- You can only use this link once
- If you didn't request this, please ignore this email

SECURITY RECOMMENDATIONS:
- Use a strong, unique password (minimum 8 characters)
- Include uppercase, lowercase, numbers, and special characters
- Don't share your password with anyone
- Enable two-factor authentication for extra security

If you didn't request a password reset, someone may be trying to access your account.

© 2025 Lovejoy's Antiques
This is an automated email. Please do not reply.
    ";
}

/**
 * Get HTML email for 2FA code
 */
function get2FACodeEmailHTML($name, $code) {
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center; }
            .content { padding: 30px; text-align: center; }
            .code { font-size: 48px; font-weight: bold; color: #667eea; letter-spacing: 10px; margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 10px; border: 2px dashed #667eea; }
            .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <div style='font-size: 48px;'>🔐</div>
                <h1>Two-Factor Authentication</h1>
            </div>
            <div class='content'>
                <h2>Hello " . htmlspecialchars($name) . "!</h2>
                <p>Your two-factor authentication code is:</p>
                
                <div class='code'>" . htmlspecialchars($code) . "</div>
                
                <p style='color: #d32f2f; font-weight: bold;'>⏰ This code will expire in 5 minutes.</p>
                
                <p style='color: #666; font-size: 14px; margin-top: 30px;'>
                    If you didn't request this code, please secure your account immediately.
                </p>
            </div>
            <div class='footer'>
                <p><strong>© 2025 Lovejoy's Antiques</strong></p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

/**
 * Get plain text email for 2FA code (fallback)
 */
function get2FACodeEmailText($name, $code) {
    return "
LOVEJOY'S ANTIQUES
Two-Factor Authentication

Hello " . $name . "!

Your two-factor authentication code is:

" . $code . "

IMPORTANT: This code will expire in 5 minutes.

If you didn't request this code, please secure your account immediately.

© 2025 Lovejoy's Antiques
This is an automated email. Please do not reply.
    ";
}

/**
 * Test SMTP connection
 * 
 * @return array ['success' => bool, 'message' => string]
 */
function testSMTPConnection() {
    $mail = new PHPMailer(true);
    
    try {
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION === 'ssl' ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;
        
        $mail->SMTPDebug = 0;
        
        // Try to connect
        $mail->smtpConnect();
        $mail->smtpClose();
        
        return [
            'success' => true,
            'message' => 'SMTP connection successful! Mail server is reachable.'
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'SMTP connection failed: ' . $mail->ErrorInfo
        ];
    }
}

/**
 * Simple email sending function (wrapper for PHPMailer)
 * Compatible with email verification system
 * 
 * @param string $to Recipient email address
 * @param string $subject Email subject
 * @param string $htmlBody HTML email body
 * @param string $altBody Plain text alternative body (optional)
 * @return bool Success status
 */
function sendEmail($to, $subject, $htmlBody, $altBody = '') {
    $mail = new PHPMailer(true);
    
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION === 'ssl' ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = SMTP_PORT;
        $mail->CharSet    = 'UTF-8';
        $mail->SMTPDebug  = 0; // Disable debug output
        
        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($to);
        $mail->addReplyTo(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        
        // Content
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $htmlBody;
        $mail->AltBody = $altBody ? $altBody : strip_tags($htmlBody);
        
        // Send email
        $mail->send();
        
        error_log("✓ Email sent successfully to: $to");
        logSecurityEvent('EMAIL_SENT', "Email sent to: $to - Subject: $subject");
        
        return true;
        
    } catch (Exception $e) {
        error_log("✗ Email failed to: $to - Error: {$mail->ErrorInfo}");
        logSecurityEvent('EMAIL_FAILED', "Failed to send email to: $to - Error: {$mail->ErrorInfo}");
        
        return false;
    }
}
?>
