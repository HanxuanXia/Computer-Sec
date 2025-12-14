<?php
/**
 * Email Verification Handler
 * Verifies user email addresses via token sent in registration email
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Initialize variables
$message = '';
$success = false;
$already_verified = false;

// Check if token is provided
if (isset($_GET['token']) && !empty($_GET['token'])) {
    $token = $_GET['token'];
    
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        // Find user with this verification token
        $query = "SELECT user_id, email, email_verified, email_verification_expires 
                  FROM users 
                  WHERE email_verification_token = :token";
        
        $stmt = $db->prepare($query);
        $stmt->execute(['token' => $token]);
        
        if ($stmt->rowCount() === 1) {
            $user = $stmt->fetch();
            
            // Check if already verified
            if ($user['email_verified']) {
                $already_verified = true;
                $message = "Your email has already been verified. You can login now.";
            }
            // Check if token expired
            else if (strtotime($user['email_verification_expires']) < time()) {
                $message = "This verification link has expired. Please request a new verification email.";
                logSecurityEvent('EMAIL_VERIFICATION_EXPIRED', "Expired token used for: " . $user['email']);
            }
            // Verify the email
            else {
                $updateQuery = "UPDATE users 
                               SET email_verified = TRUE, 
                                   email_verification_token = NULL,
                                   email_verification_expires = NULL,
                                   account_status = 'active'
                               WHERE user_id = :user_id";
                
                $updateStmt = $db->prepare($updateQuery);
                $updateStmt->execute(['user_id' => $user['user_id']]);
                
                $success = true;
                $message = "Email verified successfully! You can now login to your account.";
                logSecurityEvent('EMAIL_VERIFIED', "Email verified: " . $user['email']);
            }
        } else {
            $message = "Invalid verification token. Please check your email and try again.";
            logSecurityEvent('EMAIL_VERIFICATION_INVALID_TOKEN', "Invalid token attempted");
        }
        
    } catch (PDOException $e) {
        error_log("Email Verification Error: " . $e->getMessage());
        $message = "An error occurred during verification. Please try again.";
    }
} else {
    $message = "No verification token provided. Please check your email for the verification link.";
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - Lovejoy's Antique Evaluation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        
        .icon.success { color: #27ae60; }
        .icon.error { color: #e74c3c; }
        .icon.info { color: #3498db; }
        
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 20px;
        }
        
        .message {
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 30px;
            padding: 20px;
            border-radius: 8px;
        }
        
        .message.success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .message.error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .message.info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: transform 0.2s;
            margin: 5px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .resend-form {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($success): ?>
            <div class="icon success">✓</div>
            <h1>Email Verified!</h1>
            <div class="message success"><?php echo htmlspecialchars($message); ?></div>
            <a href="login.php" class="btn">Login Now</a>
            
        <?php elseif ($already_verified): ?>
            <div class="icon info">ℹ</div>
            <h1>Already Verified</h1>
            <div class="message info"><?php echo htmlspecialchars($message); ?></div>
            <a href="login.php" class="btn">Go to Login</a>
            
        <?php else: ?>
            <div class="icon error">✗</div>
            <h1>Verification Failed</h1>
            <div class="message error"><?php echo htmlspecialchars($message); ?></div>
            <a href="index.php" class="btn btn-secondary">Back to Home</a>
            
            <!-- Resend verification email option -->
            <div class="resend-form">
                <p style="color: #666; margin-bottom: 15px;">Need a new verification link?</p>
                <form method="POST" action="resend_verification.php">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                    <div class="form-group">
                        <input type="email" name="email" class="form-control" 
                               placeholder="Enter your email address" required>
                    </div>
                    <button type="submit" class="btn">Resend Verification Email</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
