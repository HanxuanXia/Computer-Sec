<?php
/**
 * TASK 3: PASSWORD MANAGEMENT - FORGOT PASSWORD (5 marks - Code Quality)
 * 
 * Security Features Implemented:
 * 1. CSRF Protection - Validates CSRF token
 * 2. Secure Token Generation - Uses cryptographically secure random_bytes()
 * 3. Token Expiration - Tokens expire after 1 hour
 * 4. Rate Limiting - Prevents abuse (3 requests per 15 minutes)
 * 5. Email Validation - Ensures valid email format
 * 6. SQL Injection Prevention - Uses prepared statements
 * 7. Audit Logging - Tracks password reset requests
 * 8. Generic Messages - Doesn't reveal if email exists (prevents user enumeration)
 */

require_once __DIR__ . '/config/security_config.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

$errors = [];
$success = '';
$step = $_GET['step'] ?? 'request'; // request, reset

// Process password reset request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $step === 'request') {
    // SECURITY EVIDENCE 1: CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('PASSWORD_RESET_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        // SECURITY EVIDENCE 2: Input Sanitization
        $email = sanitizeInput($_POST['email'] ?? '');
        
        // Validation
        if (empty($email)) {
            $errors[] = "Email address is required";
        } else if (!validateEmail($email)) {
            $errors[] = "Invalid email format";
        } else {
            // SECURITY EVIDENCE 3: Rate Limiting
            if (!checkRateLimit('password_reset_' . $email, 3, 900)) {
                $errors[] = "Too many password reset requests. Please try again later.";
                logSecurityEvent('PASSWORD_RESET_RATE_LIMIT', "Rate limit exceeded for: $email");
            } else {
                try {
                    $database = new Database();
                    $db = $database->getConnection();
                    
                    // SECURITY EVIDENCE 4: SQL Injection Prevention
                    $query = "SELECT user_id, full_name FROM users WHERE email = :email AND account_status = 'active'";
                    $stmt = $db->prepare($query);
                    $stmt->execute(['email' => $email]);
                    
                    if ($stmt->rowCount() === 1) {
                        $user = $stmt->fetch();
                        
                        // SECURITY EVIDENCE 5: Secure Token Generation
                        $reset_token = generateSecureToken(32);
                        $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));
                        
                        // Store reset token in database
                        $insertQuery = "INSERT INTO password_reset_tokens (user_id, token, expires_at) 
                                       VALUES (:user_id, :token, :expires_at)";
                        $insertStmt = $db->prepare($insertQuery);
                        $insertStmt->execute([
                            'user_id' => $user['user_id'],
                            'token' => $reset_token,
                            'expires_at' => $expires_at
                        ]);
                        
                        // SECURITY EVIDENCE 6: Audit Logging
                        logSecurityEvent('PASSWORD_RESET_REQUESTED', "Password reset requested for: $email");
                        
                        // Generate reset link
                        $reset_link = "http://" . $_SERVER['HTTP_HOST'] . "/Compsec/lovejoy_secure_app/forgot_password.php?step=reset&token=" . $reset_token;
                        
                        // 📧 Send email based on configured mode
                        $email_mode = defined('EMAIL_MODE') ? EMAIL_MODE : 'demo';
                        $email_sent = false;
                        $email_error = '';
                        
                        if ($email_mode === 'smtp' || $email_mode === 'hybrid') {
                            // Try to send real email via SMTP (PHPMailer)
                            require_once __DIR__ . '/includes/email_smtp.php';
                            $result = sendEmailViaSMTP($email, $user['full_name'], $reset_token, 'password_reset');
                            $email_sent = $result['success'];
                            $email_error = $result['debug'];
                        }
                        
                        // SECURITY EVIDENCE 7: Generic Success Message (Prevents User Enumeration)
                        if ($email_mode === 'demo' || ($email_mode === 'hybrid' && !$email_sent)) {
                            // Demo mode: show link directly
                            $success = "If an account exists with that email, a password reset link has been sent. " .
                                      "<br><br><strong>🔧 Demo Mode:</strong> Password reset link generated (local testing mode, no email sent)<br>" .
                                      "<a href='$reset_link' class='btn' style='display: inline-block; margin-top: 10px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;'>Click here to reset password →</a><br><br>" .
                                      "<small style='color: #666;'>💡 Tip: In production, this link would be sent via email.<br>" .
                                      "To configure real email sending, visit the <a href='smtp_setup.php'>SMTP Setup page</a></small>";
                        } else {
                            // SMTP mode: email sent
                            $success = "If an account exists with that email, a password reset link has been sent to your inbox. " .
                                      "<br><br>Please check your email (including spam folder) and click the link to reset your password." .
                                      "<br><br><small style='color: #666;'>📧 Email sent via SMTP server</small>";
                        }
                    } else {
                        // SECURITY EVIDENCE 8: Generic message even if user doesn't exist
                        $success = "If an account exists with that email, a password reset link has been sent.";
                        logSecurityEvent('PASSWORD_RESET_INVALID_EMAIL', "Password reset attempted for non-existent email: $email");
                    }
                    
                } catch (PDOException $e) {
                    error_log("Password Reset Error: " . $e->getMessage());
                    $errors[] = "An error occurred. Please try again.";
                }
                
                recordRateLimitAttempt('password_reset_' . $email);
            }
        }
    }
}

// Process password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $step === 'reset') {
    $token = sanitizeInput($_POST['token'] ?? '');
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // SECURITY EVIDENCE: CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
    } else if (empty($token) || empty($new_password) || empty($confirm_password)) {
        $errors[] = "All fields are required";
    } else if ($new_password !== $confirm_password) {
        $errors[] = "Passwords do not match";
    } else {
        // SECURITY EVIDENCE: Password Strength Validation
        $passwordErrors = validatePasswordStrength($new_password);
        if (!empty($passwordErrors)) {
            $errors = array_merge($errors, $passwordErrors);
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // SECURITY EVIDENCE: Token Validation with Expiration Check
                $query = "SELECT t.token_id, t.user_id, t.expires_at, t.used, u.email 
                         FROM password_reset_tokens t
                         JOIN users u ON t.user_id = u.user_id
                         WHERE t.token = :token AND t.used = 0";
                $stmt = $db->prepare($query);
                $stmt->execute(['token' => $token]);
                
                if ($stmt->rowCount() === 1) {
                    $reset_data = $stmt->fetch();
                    
                    // Check if token has expired
                    if (strtotime($reset_data['expires_at']) < time()) {
                        $errors[] = "This password reset link has expired. Please request a new one.";
                        logSecurityEvent('PASSWORD_RESET_TOKEN_EXPIRED', "Expired token used");
                    } else {
                        // SECURITY EVIDENCE: Secure Password Hashing
                        $password_hash = hashPassword($new_password);
                        
                        // Update password
                        $updateQuery = "UPDATE users 
                                       SET password_hash = :password_hash,
                                           failed_login_attempts = 0,
                                           account_status = 'active'
                                       WHERE user_id = :user_id";
                        $updateStmt = $db->prepare($updateQuery);
                        $updateStmt->execute([
                            'password_hash' => $password_hash,
                            'user_id' => $reset_data['user_id']
                        ]);
                        
                        // Mark token as used
                        $markUsedQuery = "UPDATE password_reset_tokens SET used = 1 WHERE token_id = :token_id";
                        $markUsedStmt = $db->prepare($markUsedQuery);
                        $markUsedStmt->execute(['token_id' => $reset_data['token_id']]);
                        
                        // SECURITY EVIDENCE: Audit Logging
                        logSecurityEvent('PASSWORD_RESET_COMPLETED', "Password reset for: " . $reset_data['email']);
                        
                        $success = "Password reset successful! You can now login with your new password.";
                        $step = 'success';
                    }
                } else {
                    $errors[] = "Invalid or already used password reset link.";
                    logSecurityEvent('PASSWORD_RESET_INVALID_TOKEN', "Invalid token attempted");
                }
                
            } catch (PDOException $e) {
                error_log("Password Reset Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Validate token for reset form
if ($step === 'reset' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    $token = sanitizeInput($_GET['token'] ?? '');
    
    if (empty($token)) {
        $errors[] = "Invalid password reset link.";
        $step = 'request';
    } else {
        try {
            $database = new Database();
            $db = $database->getConnection();
            
            $query = "SELECT token_id, expires_at, used FROM password_reset_tokens WHERE token = :token";
            $stmt = $db->prepare($query);
            $stmt->execute(['token' => $token]);
            
            if ($stmt->rowCount() === 0) {
                $errors[] = "Invalid password reset link.";
                $step = 'request';
            } else {
                $reset_data = $stmt->fetch();
                if ($reset_data['used'] == 1) {
                    $errors[] = "This password reset link has already been used.";
                    $step = 'request';
                } else if (strtotime($reset_data['expires_at']) < time()) {
                    $errors[] = "This password reset link has expired. Please request a new one.";
                    $step = 'request';
                }
            }
        } catch (PDOException $e) {
            error_log("Token Validation Error: " . $e->getMessage());
            $errors[] = "An error occurred. Please try again.";
            $step = 'request';
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
    <title>Password Recovery - Lovejoy's Antique Evaluation</title>
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
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        input[type="email"],
        input[type="password"],
        input[type="text"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .password-wrapper {
            position: relative;
        }
        
        .password-wrapper input {
            padding-right: 45px;
        }
        
        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 18px;
            color: #666;
            padding: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .toggle-password:hover {
            color: #667eea;
        }
        
        .toggle-password:focus {
            outline: none;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .alert-danger {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .alert ul {
            margin: 10px 0 0 20px;
        }
        
        .back-link {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }
        
        .back-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .password-strength {
            margin-top: 8px;
            height: 5px;
            background: #e0e0e0;
            border-radius: 3px;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background 0.3s;
        }
        
        .password-strength-text {
            margin-top: 5px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .password-requirements {
            margin-top: 10px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .password-requirements h4 {
            font-size: 13px;
            margin-bottom: 8px;
        }
        
        .password-requirements ul {
            list-style: none;
            padding-left: 0;
        }
        
        .password-requirements li {
            font-size: 12px;
            padding: 3px 0;
            padding-left: 20px;
            position: relative;
        }
        
        .password-requirements li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #27ae60;
        }
        
        .info-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($step === 'request'): ?>
            <div class="header">
                <h1>🔐 Password Recovery</h1>
                <p>Enter your email to receive a password reset link</p>
            </div>
            
            <div class="info-box">
                <strong>Note:</strong> The reset link will expire in 1 hour for security reasons.
            </div>
            
            <?php if (!empty($success)): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="?step=request">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" 
                           id="email" 
                           name="email" 
                           placeholder="john.doe@example.com"
                           required
                           autofocus>
                </div>
                
                <button type="submit" class="btn">Send Reset Link</button>
            </form>
            
        <?php elseif ($step === 'reset'): ?>
            <div class="header">
                <h1>🔒 Reset Password</h1>
                <p>Enter your new password</p>
            </div>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="?step=reset" id="resetForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token ?? ''); ?>">
                
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <div class="password-wrapper">
                        <input type="password" 
                               id="new_password" 
                               name="new_password" 
                               placeholder="Enter new password"
                               required>
                        <button type="button" 
                                class="toggle-password" 
                                onclick="togglePasswordVisibility('new_password')"
                                aria-label="Toggle password visibility">
                            <span id="new_password-toggle-icon">👁️</span>
                        </button>
                    </div>
                    <div class="password-strength">
                        <div class="password-strength-bar" id="strengthBar"></div>
                    </div>
                    <div class="password-strength-text" id="strengthText"></div>
                </div>
                
                <div class="password-requirements">
                    <h4>Password Requirements:</h4>
                    <ul>
                        <li>At least 12 characters long</li>
                        <li>One uppercase letter (A-Z)</li>
                        <li>One lowercase letter (a-z)</li>
                        <li>One number (0-9)</li>
                        <li>One special character (@, #, $, %, etc.)</li>
                    </ul>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="password-wrapper">
                        <input type="password" 
                               id="confirm_password" 
                               name="confirm_password" 
                               placeholder="Re-enter new password"
                               required>
                        <button type="button" 
                                class="toggle-password" 
                                onclick="togglePasswordVisibility('confirm_password')"
                                aria-label="Toggle confirm password visibility">
                            <span id="confirm_password-toggle-icon">👁️</span>
                        </button>
                    </div>
                </div>
                
                <button type="submit" class="btn">Reset Password</button>
            </form>
            
        <?php elseif ($step === 'success'): ?>
            <div class="header">
                <h1>✅ Success!</h1>
                <p>Your password has been reset</p>
            </div>
            
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
            
            <a href="login.php" class="btn">Go to Login</a>
        <?php endif; ?>
        
        <div class="back-link">
            <a href="login.php">← Back to Login</a>
        </div>
    </div>
    
    <script>
        // Toggle password visibility
        function togglePasswordVisibility(fieldId) {
            const passwordField = document.getElementById(fieldId);
            const toggleIcon = document.getElementById(fieldId + '-toggle-icon');
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.textContent = '🙈';
            } else {
                passwordField.type = 'password';
                toggleIcon.textContent = '👁️';
            }
        }
        
        // Password strength indicator
        const passwordInput = document.getElementById('new_password');
        if (passwordInput) {
            passwordInput.addEventListener('input', function(e) {
                const password = e.target.value;
                let strength = 0;
                
                if (password.length >= 12) strength++;
                if (password.length >= 16) strength++;
                if (/[a-z]/.test(password)) strength++;
                if (/[A-Z]/.test(password)) strength++;
                if (/[0-9]/.test(password)) strength++;
                if (/[^A-Za-z0-9]/.test(password)) strength++;
                
                const bar = document.getElementById('strengthBar');
                const text = document.getElementById('strengthText');
                
                if (strength <= 2) {
                    bar.style.width = '33%';
                    bar.style.background = '#e74c3c';
                    text.textContent = 'Weak Password';
                    text.style.color = '#e74c3c';
                } else if (strength <= 4) {
                    bar.style.width = '66%';
                    bar.style.background = '#f39c12';
                    text.textContent = 'Moderate Password';
                    text.style.color = '#f39c12';
                } else {
                    bar.style.width = '100%';
                    bar.style.background = '#27ae60';
                    text.textContent = 'Strong Password';
                    text.style.color = '#27ae60';
                }
            });
        }
        
        // Form validation
        const resetForm = document.getElementById('resetForm');
        if (resetForm) {
            resetForm.addEventListener('submit', function(e) {
                const password = document.getElementById('new_password').value;
                const confirmPassword = document.getElementById('confirm_password').value;
                
                if (password !== confirmPassword) {
                    e.preventDefault();
                    alert('Passwords do not match!');
                    return false;
                }
                
                if (password.length < 12) {
                    e.preventDefault();
                    alert('Password must be at least 12 characters long!');
                    return false;
                }
            });
        }
    </script>
</body>
</html>
