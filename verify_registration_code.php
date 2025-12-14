<?php
/**
 * Email Verification Code Entry Page
 * Users enter their 6-digit code to verify their email after registration
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/email_verification.php';
require_once __DIR__ . '/config/security_config.php';

session_start();

// Check if email is in session (passed from registration)
if (!isset($_SESSION['pending_verification_email'])) {
    // If no email in session, show form to enter email
    $show_email_form = true;
} else {
    $email = $_SESSION['pending_verification_email'];
    $show_email_form = false;
}

$errors = [];
$success = '';
$resend_success = '';

// Handle verification code submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if (isset($_POST['action']) && $_POST['action'] === 'resend') {
        // Resend verification code
        if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
            $errors[] = "Invalid security token. Please try again.";
        } else {
            $resend_email = $_POST['email'] ?? $email ?? '';
            if (empty($resend_email)) {
                $errors[] = "Email address is required.";
            } else {
                $result = resendVerificationCode($resend_email);
                if ($result['success']) {
                    $resend_success = $result['message'];
                    $email = $resend_email;
                    $_SESSION['pending_verification_email'] = $email;
                    $show_email_form = false;
                } else {
                    $errors[] = $result['message'];
                }
            }
        }
    } else {
        // Verify code
        if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
            $errors[] = "Invalid security token. Please try again.";
            logSecurityEvent('VERIFICATION_CSRF_FAILED', 'Invalid CSRF token on email verification');
        } else {
            $verify_email = sanitizeInput($_POST['email'] ?? '');
            $code = sanitizeInput($_POST['verification_code'] ?? '');
            
            // Validate inputs
            if (empty($verify_email)) {
                $errors[] = "Email address is required.";
            } elseif (!validateEmail($verify_email)) {
                $errors[] = "Invalid email address format.";
            }
            
            if (empty($code)) {
                $errors[] = "Verification code is required.";
            } elseif (!preg_match('/^[0-9]{6}$/', $code)) {
                $errors[] = "Verification code must be 6 digits.";
            }
            
            if (empty($errors)) {
                // Attempt verification
                $result = verifyEmailCode($verify_email, $code);
                
                if ($result['success']) {
                    $success = $result['message'];
                    logSecurityEvent('EMAIL_VERIFIED', "Email verified successfully: $verify_email");
                    
                    // Clear session
                    unset($_SESSION['pending_verification_email']);
                    
                    // Redirect to login after 3 seconds
                    header("refresh:3;url=login.php");
                } else {
                    $errors[] = $result['message'];
                    logSecurityEvent('EMAIL_VERIFICATION_FAILED', "Failed verification for: $verify_email - " . $result['message']);
                }
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
    <title>Verify Your Email - Lovejoy's Antique Evaluation</title>
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
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 100%;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: #8b7355;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .logo p {
            color: #666;
            font-size: 14px;
        }
        
        .verification-icon {
            text-align: center;
            font-size: 60px;
            margin-bottom: 20px;
        }
        
        h2 {
            color: #333;
            text-align: center;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        .info-box {
            background-color: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .info-box p {
            color: #1976D2;
            font-size: 14px;
            margin: 5px 0;
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        
        input[type="email"],
        input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="text"].code-input {
            text-align: center;
            font-size: 24px;
            letter-spacing: 8px;
            font-weight: bold;
        }
        
        input:focus {
            outline: none;
            border-color: #8b7355;
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            background-color: #8b7355;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .btn:hover {
            background-color: #6d5840;
        }
        
        .btn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
        
        .btn-secondary {
            background-color: #6c757d;
            margin-top: 10px;
        }
        
        .btn-secondary:hover {
            background-color: #545b62;
        }
        
        .links {
            text-align: center;
            margin-top: 20px;
        }
        
        .links a {
            color: #8b7355;
            text-decoration: none;
            font-size: 14px;
        }
        
        .links a:hover {
            text-decoration: underline;
        }
        
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #999;
            font-size: 14px;
        }
        
        .email-display {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            font-weight: 500;
            color: #333;
            margin-bottom: 20px;
        }
        
        @media (max-width: 600px) {
            .container {
                padding: 30px 20px;
            }
            
            .logo h1 {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>🏛️ Lovejoy's Antiques</h1>
            <p>Professional Antique Evaluation Services</p>
        </div>
        
        <?php if ($success): ?>
            <div class="verification-icon">✅</div>
            <h2>Email Verified!</h2>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
            <div class="info-box">
                <p>✓ Your email has been successfully verified.</p>
                <p>✓ You will be redirected to the login page in 3 seconds...</p>
                <p>✓ You can now log in and set up Two-Factor Authentication.</p>
            </div>
            <a href="login.php" class="btn">Go to Login Now</a>
        <?php else: ?>
            <div class="verification-icon">📧</div>
            <h2>Verify Your Email</h2>
            
            <?php if ($resend_success): ?>
                <div class="alert alert-success">
                    <?php echo htmlspecialchars($resend_success); ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-error">
                    <?php foreach ($errors as $error): ?>
                        <div><?php echo htmlspecialchars($error); ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if (!$show_email_form): ?>
                <div class="info-box">
                    <p><strong>📬 Check your email!</strong></p>
                    <p>We've sent a 6-digit verification code to:</p>
                </div>
                
                <div class="email-display">
                    <?php echo htmlspecialchars($email); ?>
                </div>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
                    
                    <div class="form-group">
                        <label for="verification_code">Enter Verification Code:</label>
                        <input type="text" 
                               id="verification_code" 
                               name="verification_code" 
                               class="code-input"
                               placeholder="000000"
                               maxlength="6"
                               pattern="[0-9]{6}"
                               required
                               autofocus
                               inputmode="numeric">
                    </div>
                    
                    <button type="submit" class="btn">Verify Email</button>
                </form>
                
                <div class="divider">Didn't receive the code?</div>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
                    <input type="hidden" name="action" value="resend">
                    <button type="submit" class="btn btn-secondary">Resend Code</button>
                </form>
                
            <?php else: ?>
                <div class="info-box">
                    <p>Enter your email address to receive a verification code.</p>
                </div>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="action" value="resend">
                    
                    <div class="form-group">
                        <label for="email">Email Address:</label>
                        <input type="email" 
                               id="email" 
                               name="email" 
                               required
                               autofocus
                               placeholder="your.email@example.com">
                    </div>
                    
                    <button type="submit" class="btn">Send Verification Code</button>
                </form>
            <?php endif; ?>
            
            <div class="links">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Auto-submit when 6 digits entered
        document.addEventListener('DOMContentLoaded', function() {
            const codeInput = document.getElementById('verification_code');
            if (codeInput) {
                codeInput.addEventListener('input', function(e) {
                    // Remove non-numeric characters
                    this.value = this.value.replace(/[^0-9]/g, '');
                    
                    // Auto-submit when 6 digits entered
                    if (this.value.length === 6) {
                        // Optional: add a small delay for better UX
                        setTimeout(() => {
                            this.form.submit();
                        }, 300);
                    }
                });
            }
        });
    </script>
</body>
</html> -->
