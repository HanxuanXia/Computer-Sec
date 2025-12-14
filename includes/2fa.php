<?php
/**
 * TWO-FACTOR AUTHENTICATION (2FA) IMPLEMENTATION
 * Using TOTP (Time-based One-Time Password) - Compatible with Google Authenticator
 */

/**
 * Generate 2FA Secret Key
 * Creates a base32-encoded secret for TOTP
 * 
 * @return string Secret key
 */
function generate2FASecret() {
    $secret = '';
    $validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 alphabet
    
    // Generate 16-character secret (80 bits of entropy)
    for ($i = 0; $i < 16; $i++) {
        $secret .= $validChars[random_int(0, 31)];
    }
    
    return $secret;
}

/**
 * Generate QR Code URL for Google Authenticator
 * Uses local QR code generator (generate_qr.php)
 * 
 * @param string $secret 2FA secret key
 * @param string $email User email
 * @param string $issuer Application name
 * @return string QR code image URL
 */
function generate2FAQRCode($secret, $email, $issuer = "Lovejoy's Antiques") {
    // Use local QR code generator instead of external API
    $qrCodeUrl = 'generate_qr.php?secret=' . urlencode($secret) . 
                 '&email=' . urlencode($email) . 
                 '&issuer=' . urlencode($issuer);
    
    return $qrCodeUrl;
}

/**
 * Verify TOTP Code
 * Validates 6-digit code from Google Authenticator
 * 
 * @param string $secret User's 2FA secret
 * @param string $code 6-digit code from user
 * @param int $window Time window (default: ±1 period = 30 seconds tolerance)
 * @return bool True if code is valid
 */
function verify2FACode($secret, $code, $window = 1) {
    // Remove spaces and ensure 6 digits
    $code = str_replace(' ', '', $code);
    if (strlen($code) !== 6 || !ctype_digit($code)) {
        return false;
    }
    
    $timestamp = floor(time() / 30); // TOTP uses 30-second intervals
    
    // Check code within time window (allows for clock drift)
    for ($i = -$window; $i <= $window; $i++) {
        $calculatedCode = generateTOTP($secret, $timestamp + $i);
        if (hash_equals($calculatedCode, $code)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Generate TOTP Code
 * Internal function to generate time-based code
 * 
 * @param string $secret Base32 secret
 * @param int $timestamp Time counter
 * @return string 6-digit code
 */
function generateTOTP($secret, $timestamp) {
    // Decode base32 secret
    $key = base32Decode($secret);
    
    // Pack timestamp as 8-byte big-endian
    $time = pack('N*', 0) . pack('N*', $timestamp);
    
    // Generate HMAC-SHA1 hash
    $hash = hash_hmac('sha1', $time, $key, true);
    
    // Dynamic truncation (extract 4 bytes)
    $offset = ord($hash[19]) & 0x0F;
    $code = (
        ((ord($hash[$offset + 0]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    ) % 1000000;
    
    // Return 6-digit code with leading zeros
    return str_pad($code, 6, '0', STR_PAD_LEFT);
}

/**
 * Base32 Decode
 * Decodes base32-encoded string
 * 
 * @param string $input Base32 string
 * @return string Decoded binary string
 */
function base32Decode($input) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output = '';
    $v = 0;
    $vbits = 0;
    
    for ($i = 0, $j = strlen($input); $i < $j; $i++) {
        $v <<= 5;
        $v += strpos($alphabet, $input[$i]);
        $vbits += 5;
        
        if ($vbits >= 8) {
            $vbits -= 8;
            $output .= chr($v >> $vbits);
            $v &= ((1 << $vbits) - 1);
        }
    }
    
    return $output;
}

/**
 * Generate Backup Codes
 * Creates 10 one-time use backup codes
 * 
 * @return array Array of 10 backup codes
 */
function generateBackupCodes() {
    $codes = [];
    
    for ($i = 0; $i < 10; $i++) {
        // Generate 8-character alphanumeric code
        $code = bin2hex(random_bytes(4));
        $codes[] = strtoupper($code);
    }
    
    return $codes;
}

/**
 * Send 2FA Setup Email
 * Sends confirmation email after 2FA setup
 * 
 * @param string $email User email
 * @param string $name User name
 * @return bool Success status
 */
function send2FASetupConfirmation($email, $name) {
    $subject = "2FA Enabled - Lovejoy's Antiques";
    
    $message = "
    <html>
    <body style='font-family: Arial, sans-serif;'>
        <div style='max-width: 600px; margin: 0 auto;'>
            <h2>🔐 Two-Factor Authentication Enabled</h2>
            <p>Hello " . htmlspecialchars($name) . ",</p>
            <p>Two-factor authentication has been successfully enabled on your account.</p>
            <p><strong>Your account is now more secure!</strong></p>
            <p>If you didn't enable this, please contact support immediately.</p>
            <hr>
            <p style='font-size: 12px; color: #666;'>© 2025 Lovejoy's Antiques</p>
        </div>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Lovejoy's Antiques <noreply@lovejoy-antiques.com>" . "\r\n";
    
    return mail($email, $subject, $message, $headers);
}
?>
