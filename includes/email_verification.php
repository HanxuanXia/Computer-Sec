<?php
/**
 * Email Verification Code Functions
 * Handles 6-digit verification code generation, sending, and validation
 */

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/email_smtp.php';

/**
 * Generate a 6-digit verification code
 * @return string 6-digit numeric code
 */
function generateVerificationCode() {
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

/**
 * Store verification code in database
 * @param string $email User's email address
 * @param string $code 6-digit verification code
 * @param int|null $user_id Optional user ID if user already created
 * @param int $expiry_minutes How long the code is valid (default 15 minutes)
 * @return bool Success status
 */
function storeVerificationCode($email, $code, $user_id = null, $expiry_minutes = 15) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        // Delete any existing codes for this email
        $deleteQuery = "DELETE FROM email_verification_codes WHERE email = :email AND verified = 0";
        $deleteStmt = $db->prepare($deleteQuery);
        $deleteStmt->execute(['email' => $email]);
        
        // Insert new verification code
        $expires_at = date('Y-m-d H:i:s', time() + ($expiry_minutes * 60));
        $insertQuery = "INSERT INTO email_verification_codes (email, verification_code, user_id, expires_at) 
                       VALUES (:email, :code, :user_id, :expires_at)";
        $insertStmt = $db->prepare($insertQuery);
        
        return $insertStmt->execute([
            'email' => $email,
            'code' => $code,
            'user_id' => $user_id,
            'expires_at' => $expires_at
        ]);
    } catch (PDOException $e) {
        error_log("Store verification code error: " . $e->getMessage());
        return false;
    }
}

/**
 * Send verification code via email
 * @param string $email Recipient email address
 * @param string $name Recipient name
 * @param string $code 6-digit verification code
 * @return bool Success status
 */
function sendVerificationCodeEmail($email, $name, $code) {
    $subject = "Your Verification Code - Lovejoy's Antique Evaluation";
    
    $message = "
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #8b7355; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
            .content { background-color: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-top: none; }
            .code-box { background-color: #fff; border: 2px solid #8b7355; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px; }
            .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #8b7355; }
            .footer { background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 5px 5px; }
            .warning { color: #d9534f; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Email Verification</h1>
            </div>
            <div class='content'>
                <p>Hello " . htmlspecialchars($name) . ",</p>
                
                <p>Thank you for registering with Lovejoy's Antique Evaluation!</p>
                
                <p>To complete your registration, please enter the verification code below:</p>
                
                <div class='code-box'>
                    <div class='code'>" . htmlspecialchars($code) . "</div>
                </div>
                
                <p><strong>This code will expire in 15 minutes.</strong></p>
                
                <p>If you didn't create an account with us, please ignore this email.</p>
                
                <p class='warning'>⚠️ Never share this code with anyone. Our team will never ask for your verification code.</p>
            </div>
            <div class='footer'>
                <p>&copy; " . date('Y') . " Lovejoy's Antique Evaluation. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    ";
    
    return sendEmail($email, $subject, $message);
}

/**
 * Verify a code entered by the user
 * @param string $email User's email address
 * @param string $code Code entered by user
 * @return array Result with 'success' boolean and 'message' or 'user_id'
 */
function verifyEmailCode($email, $code) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        // Look up the verification code
        $query = "SELECT id, user_id, expires_at, attempts, verified 
                 FROM email_verification_codes 
                 WHERE email = :email AND verification_code = :code 
                 ORDER BY created_at DESC LIMIT 1";
        $stmt = $db->prepare($query);
        $stmt->execute([
            'email' => $email,
            'code' => $code
        ]);
        
        $record = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$record) {
            return [
                'success' => false,
                'message' => 'Invalid verification code. Please check and try again.'
            ];
        }
        
        // Check if already verified
        if ($record['verified']) {
            return [
                'success' => false,
                'message' => 'This verification code has already been used.'
            ];
        }
        
        // Check if expired
        if (strtotime($record['expires_at']) < time()) {
            return [
                'success' => false,
                'message' => 'This verification code has expired. Please request a new one.'
            ];
        }
        
        // Check attempts (max 5 attempts)
        if ($record['attempts'] >= 5) {
            return [
                'success' => false,
                'message' => 'Too many verification attempts. Please request a new code.'
            ];
        }
        
        // Increment attempts
        $updateQuery = "UPDATE email_verification_codes 
                       SET attempts = attempts + 1 
                       WHERE id = :id";
        $updateStmt = $db->prepare($updateQuery);
        $updateStmt->execute(['id' => $record['id']]);
        
        // Mark as verified
        $verifyQuery = "UPDATE email_verification_codes 
                       SET verified = 1 
                       WHERE id = :id";
        $verifyStmt = $db->prepare($verifyQuery);
        $verifyStmt->execute(['id' => $record['id']]);
        
        // Update user's email_verified status if user exists
        if ($record['user_id']) {
            $userQuery = "UPDATE users 
                         SET email_verified = 1, 
                             account_status = 'active' 
                         WHERE user_id = :user_id";
            $userStmt = $db->prepare($userQuery);
            $userStmt->execute(['user_id' => $record['user_id']]);
        }
        
        return [
            'success' => true,
            'user_id' => $record['user_id'],
            'message' => 'Email verified successfully!'
        ];
        
    } catch (PDOException $e) {
        error_log("Verify email code error: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'An error occurred during verification. Please try again.'
        ];
    }
}

/**
 * Resend verification code
 * @param string $email User's email address
 * @return array Result with 'success' boolean and 'message'
 */
function resendVerificationCode($email) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        // Check if user exists
        $userQuery = "SELECT user_id, full_name, email_verified FROM users WHERE email = :email";
        $userStmt = $db->prepare($userQuery);
        $userStmt->execute(['email' => $email]);
        $user = $userStmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return [
                'success' => false,
                'message' => 'No account found with this email address.'
            ];
        }
        
        if ($user['email_verified']) {
            return [
                'success' => false,
                'message' => 'This email address is already verified.'
            ];
        }
        
        // Generate new code
        $code = generateVerificationCode();
        
        // Store code
        if (!storeVerificationCode($email, $code, $user['user_id'])) {
            return [
                'success' => false,
                'message' => 'Failed to generate verification code. Please try again.'
            ];
        }
        
        // Send email
        if (!sendVerificationCodeEmail($email, $user['full_name'], $code)) {
            return [
                'success' => false,
                'message' => 'Failed to send verification email. Please try again.'
            ];
        }
        
        return [
            'success' => true,
            'message' => 'A new verification code has been sent to your email.'
        ];
        
    } catch (PDOException $e) {
        error_log("Resend verification code error: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'An error occurred. Please try again.'
        ];
    }
}

/**
 * Clean up expired verification codes (should be run periodically)
 */
function cleanupExpiredCodes() {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $query = "DELETE FROM email_verification_codes 
                 WHERE expires_at < NOW() AND verified = 0";
        $stmt = $db->prepare($query);
        $stmt->execute();
        
        return $stmt->rowCount();
    } catch (PDOException $e) {
        error_log("Cleanup expired codes error: " . $e->getMessage());
        return 0;
    }
}
