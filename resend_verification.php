<?php
/**
 * Resend Email Verification
 * Allows users to request a new verification email
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/email.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

$message = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $message = "Invalid security token. Please try again.";
    } else {
        $email = sanitizeInput($_POST['email'] ?? '');
        
        if (empty($email) || !validateEmail($email)) {
            $message = "Please provide a valid email address.";
        } else {
            // Rate limiting
            if (!checkRateLimit($email, 3, 3600)) { // 3 attempts per hour
                $message = "Too many requests. Please try again later.";
                logSecurityEvent('RESEND_VERIFICATION_RATE_LIMIT', "Rate limit exceeded for: $email");
            } else {
                try {
                    $database = new Database();
                    $db = $database->getConnection();
                    
                    // Find user
                    $query = "SELECT user_id, email, email_verified, full_name 
                              FROM users 
                              WHERE email = :email";
                    
                    $stmt = $db->prepare($query);
                    $stmt->execute(['email' => $email]);
                    
                    if ($stmt->rowCount() === 1) {
                        $user = $stmt->fetch();
                        
                        if ($user['email_verified']) {
                            // Already verified - don't reveal this to prevent enumeration
                            $success = true;
                            $message = "If your email is in our system and not yet verified, you will receive a verification link shortly.";
                        } else {
                            // Generate new verification token
                            $token = bin2hex(random_bytes(32));
                            $expires = date('Y-m-d H:i:s', time() + EMAIL_VERIFICATION_TOKEN_EXPIRY);
                            
                            // Update user with new token
                            $updateQuery = "UPDATE users 
                                           SET email_verification_token = :token,
                                               email_verification_expires = :expires
                                           WHERE user_id = :user_id";
                            
                            $updateStmt = $db->prepare($updateQuery);
                            $updateStmt->execute([
                                'token' => $token,
                                'expires' => $expires,
                                'user_id' => $user['user_id']
                            ]);
                            
                            // Send verification email
                            $verificationLink = rtrim(BASE_URL, '/') . '/verify_email.php?token=' . $token;
                            
                            $result = sendVerificationEmail(
                                $user['email'],
                                $user['full_name'],
                                $verificationLink
                            );
                            
                            if ($result) {
                                $success = true;
                                $message = "Verification email sent! Please check your inbox and spam folder.";
                                logSecurityEvent('VERIFICATION_EMAIL_RESENT', "Verification email resent to: $email");
                            } else {
                                $message = "Failed to send verification email. Please try again later.";
                            }
                        }
                    } else {
                        // User not found - don't reveal this (security best practice)
                        $success = true;
                        $message = "If your email is in our system and not yet verified, you will receive a verification link shortly.";
                        logSecurityEvent('RESEND_VERIFICATION_UNKNOWN_EMAIL', "Verification resend requested for unknown email: $email");
                    }
                    
                } catch (PDOException $e) {
                    error_log("Resend Verification Error: " . $e->getMessage());
                    $message = "An error occurred. Please try again.";
                }
                
                recordRateLimitAttempt($email);
            }
        }
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resend Verification Email - Lovejoy's Antique Evaluation</title>
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
        }
        
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .subtitle {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
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
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .back-link a {
            color: #667eea;
            text-decoration: none;
        }
        
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📧 Resend Verification Email</h1>
        <p class="subtitle">Enter your email to receive a new verification link</p>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($message); ?>
            </div>
            <div class="back-link">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php else: ?>
            <?php if (!empty($message)): ?>
                <div class="alert alert-error">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" 
                           id="email" 
                           name="email" 
                           class="form-control" 
                           placeholder="your.email@example.com"
                           required
                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
                </div>
                
                <button type="submit" class="btn">Send Verification Email</button>
            </form>
            
            <div class="back-link">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
