<?php
/**
 * EMAIL VERIFICATION IMPLEMENTATION
 * Sends real emails with verification links
 */

/**
 * Send verification email
 * 
 * @param string $to Recipient email
 * @param string $name Recipient name
 * @param string $token Verification token
 * @param string $type Type: 'registration' or 'password_reset'
 * @return bool Success status
 */
function sendVerificationEmail($to, $name, $token, $type = 'registration') {
    $base_url = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/";
    
    if ($type === 'registration') {
        $subject = "Verify Your Email - Lovejoy's Antiques";
        $verify_link = $base_url . "verify_email.php?token=" . $token;
        
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>🏺 Lovejoy's Antiques</h1>
                    <p>Welcome to our antique evaluation service</p>
                </div>
                <div class='content'>
                    <h2>Hello " . htmlspecialchars($name) . "!</h2>
                    <p>Thank you for registering with Lovejoy's Antiques. Please verify your email address to activate your account.</p>
                    
                    <p><a href='" . $verify_link . "' class='button'>Verify Email Address</a></p>
                    
                    <p>Or copy and paste this link into your browser:</p>
                    <p style='background: #fff; padding: 10px; border: 1px solid #ddd; word-break: break-all;'>" . $verify_link . "</p>
                    
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    
                    <p>If you didn't create this account, please ignore this email.</p>
                </div>
                <div class='footer'>
                    <p>© 2025 Lovejoy's Antiques. All rights reserved.</p>
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        ";
        
    } else if ($type === 'password_reset') {
        $subject = "Reset Your Password - Lovejoy's Antiques";
        $reset_link = $base_url . "forgot_password.php?step=reset&token=" . $token;
        
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>🔐 Password Reset Request</h1>
                </div>
                <div class='content'>
                    <h2>Hello " . htmlspecialchars($name) . "!</h2>
                    <p>We received a request to reset your password for your Lovejoy's Antiques account.</p>
                    
                    <p><a href='" . $reset_link . "' class='button'>Reset Password</a></p>
                    
                    <p>Or copy and paste this link into your browser:</p>
                    <p style='background: #fff; padding: 10px; border: 1px solid #ddd; word-break: break-all;'>" . $reset_link . "</p>
                    
                    <div class='warning'>
                        <strong>⚠️ Security Notice:</strong>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>You can only use this link once</li>
                            <li>If you didn't request this, please ignore this email</li>
                        </ul>
                    </div>
                    
                    <p>For security reasons, we recommend:</p>
                    <ul>
                        <li>Using a strong, unique password</li>
                        <li>Not sharing your password with anyone</li>
                        <li>Enabling two-factor authentication</li>
                    </ul>
                </div>
                <div class='footer'>
                    <p>© 2025 Lovejoy's Antiques. All rights reserved.</p>
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        ";
    }
    
    // Email headers
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Lovejoy's Antiques <noreply@lovejoy-antiques.com>" . "\r\n";
    $headers .= "Reply-To: support@lovejoy-antiques.com" . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();
    
    // Send email
    $result = mail($to, $subject, $message, $headers);
    
    if ($result) {
        logSecurityEvent('EMAIL_SENT', "Verification email sent to: $to (Type: $type)");
    } else {
        error_log("Failed to send email to: $to");
    }
    
    return $result;
}

/**
 * Send 2FA code via email
 * 
 * @param string $to Recipient email
 * @param string $name Recipient name
 * @param string $code 6-digit code
 * @return bool Success status
 */
function send2FACode($to, $name, $code) {
    $subject = "Your 2FA Code - Lovejoy's Antiques";
    
    $message = "
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; text-align: center; }
            .code { font-size: 48px; font-weight: bold; color: #667eea; letter-spacing: 10px; margin: 30px 0; padding: 20px; background: white; border-radius: 10px; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>🔐 Two-Factor Authentication</h1>
            </div>
            <div class='content'>
                <h2>Hello " . htmlspecialchars($name) . "!</h2>
                <p>Your two-factor authentication code is:</p>
                
                <div class='code'>" . htmlspecialchars($code) . "</div>
                
                <p><strong>This code will expire in 5 minutes.</strong></p>
                
                <p>If you didn't request this code, please secure your account immediately.</p>
            </div>
            <div class='footer'>
                <p>© 2025 Lovejoy's Antiques. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Lovejoy's Antiques <noreply@lovejoy-antiques.com>" . "\r\n";
    
    return mail($to, $subject, $message, $headers);
}
?>
