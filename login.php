<?php
/**
 * TASK 2: SECURE LOGIN FEATURE (5 marks - Code Quality)
 * 
 * Security Features Implemented:
 * 1. CSRF Protection - Validates CSRF token on login attempts
 * 2. SQL Injection Prevention - Uses PDO prepared statements
 * 3. Brute Force Protection - Rate limiting (5 attempts per 15 minutes)
 * 4. Account Lockout - Locks account after 5 failed login attempts
 * 5. Secure Password Verification - Uses timing-safe password_verify()
 * 6. Session Security - Regenerates session ID after login
 * 7. Audit Logging - Tracks all login attempts (success and failure)
 * 8. Input Sanitization - Prevents XSS attacks
 * 9. Two-Factor Authentication - Requires 2FA code if enabled
 * 10. Email Verification Check - Blocks login if email not verified
 * 11. Google reCAPTCHA v2 - Prevents automated login attacks
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

// Initialize variables
$errors = [];
$success = '';

// Debug mode (only for development - remove in production)
$debug_mode = isset($_GET['debug']) && $_GET['debug'] === '1';

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY EVIDENCE 1: CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        if ($debug_mode) {
            $errors[] = "DEBUG: Session ID: " . session_id();
            $errors[] = "DEBUG: Session token: " . ($_SESSION['csrf_token'] ?? 'NOT SET');
            $errors[] = "DEBUG: Posted token: " . ($_POST['csrf_token'] ?? 'NOT SET');
        }
        logSecurityEvent('LOGIN_CSRF_FAILED', 'Invalid CSRF token on login');
    } else {
        // SECURITY EVIDENCE 2: Input Sanitization (XSS Prevention)
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        
        // Basic validation
        if (empty($email) || empty($password)) {
            $errors[] = "Email and password are required";
        } else if (!validateEmail($email)) {
            $errors[] = "Invalid email format";
        } else {
            // SECURITY EVIDENCE 3: Rate Limiting (Brute Force Protection)
            if (!checkRateLimit($email, 5, 900)) { // 5 attempts per 15 minutes
                $errors[] = "Too many login attempts. Please try again in 15 minutes.";
                logSecurityEvent('LOGIN_RATE_LIMIT_EXCEEDED', "Too many login attempts for: $email");
            } else {
                try {
                    $database = new Database();
                    $db = $database->getConnection();
                    
                    // SECURITY EVIDENCE 4: SQL Injection Prevention (Prepared Statement)
                    $query = "SELECT user_id, email, password_hash, full_name, phone_number, role, 
                                     account_status, failed_login_attempts, two_factor_enabled, email_verified 
                              FROM users 
                              WHERE email = :email";
                    
                    $stmt = $db->prepare($query);
                    $stmt->execute(['email' => $email]);
                    
                    if ($stmt->rowCount() === 1) {
                        $user = $stmt->fetch();
                        
                        // SECURITY EVIDENCE 6: Account Lockout Check
                        if ($user['account_status'] === 'locked') {
                            $errors[] = "Your account has been locked due to multiple failed login attempts. Please contact support.";
                            logSecurityEvent('LOGIN_LOCKED_ACCOUNT', "Attempt to login to locked account: $email");
                        }
                        // SECURITY EVIDENCE 7: Email Verification Check
                        else if (!$user['email_verified']) {
                            $errors[] = "Please verify your email address before logging in.";
                            $errors[] = "<a href='verify_registration_code.php' style='color: #8b7355; text-decoration: underline;'>Click here to enter your verification code</a>";
                            logSecurityEvent('LOGIN_UNVERIFIED_EMAIL', "Login attempt with unverified email: $email");
                            // Store email in session for easy resend
                            session_start();
                            $_SESSION['pending_verification_email'] = $email;
                        }
                        else {
                            // SECURITY EVIDENCE 5: Secure Password Verification (Timing-Safe)
                            if (verifyPassword($password, $user['password_hash'])) {
                                // Password correct! Now verify reCAPTCHA
                                
                                // SECURITY EVIDENCE 6: Google reCAPTCHA Verification (AFTER password check)
                                if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['login']) {
                                    $version = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v3';
                                    
                                    if ($version === 'v2') {
                                        // v2 Checkbox - response comes from g-recaptcha-response
                                        $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';
                                    } else {
                                        // v3 Invisible - token from hidden field
                                        $recaptchaResponse = $_POST['recaptcha_token'] ?? '';
                                    }
                                    
                                    error_log("DEBUG [Login]: reCAPTCHA response received, length=" . strlen($recaptchaResponse));
                                    
                                    $recaptchaResult = verifyRecaptcha($recaptchaResponse, 'login');
                                    
                                    if (!$recaptchaResult['success']) {
                                        $errors[] = "Bot verification failed. Please try again.";
                                        error_log("DEBUG [Login]: reCAPTCHA verification failed - " . $recaptchaResult['error']);
                                        logSecurityEvent('LOGIN_RECAPTCHA_FAILED', 'reCAPTCHA failed after password verification: ' . $recaptchaResult['error']);
                                    } else if ($version === 'v3' && $recaptchaResult['score'] < RECAPTCHA_SCORE_THRESHOLD) {
                                        $errors[] = "Suspicious activity detected. Please try again later.";
                                        error_log("DEBUG [Login]: Low reCAPTCHA score - " . $recaptchaResult['score']);
                                        logSecurityEvent('LOGIN_LOW_RECAPTCHA_SCORE', "Low score after password verification: " . $recaptchaResult['score']);
                                    } else {
                                        error_log("DEBUG [Login]: ✓ reCAPTCHA passed, score=" . $recaptchaResult['score']);
                                    }
                                }
                                
                                // If reCAPTCHA failed, don't proceed
                                if (!empty($errors)) {
                                    // reCAPTCHA failed, but don't increment failed login attempts
                                    // since password was correct
                                } else {
                                    // Both password and reCAPTCHA passed!
                                    
                                    // Reset failed login attempts
                                    $updateQuery = "UPDATE users 
                                                   SET failed_login_attempts = 0, 
                                                       last_login = NOW() 
                                                   WHERE user_id = :user_id";
                                    $updateStmt = $db->prepare($updateQuery);
                                    $updateStmt->execute(['user_id' => $user['user_id']]);
                                    
                                    // SECURITY EVIDENCE 7: Two-Factor Authentication Check
                                    if (TWO_FACTOR_ENABLED && $user['two_factor_enabled']) {
                                        // Require 2FA verification
                                        session_regenerate_id(true);
                                        $_SESSION['2fa_user_id'] = $user['user_id'];
                                        $_SESSION['2fa_email'] = $user['email'];
                                        $_SESSION['2fa_full_name'] = $user['full_name'];
                                        
                                        logSecurityEvent('LOGIN_2FA_REQUIRED', "2FA required for: $email");
                                        
                                        // Redirect to 2FA verification page
                                        header('Location: verify_2fa.php');
                                        exit();
                                    } else {
                                        // No 2FA - Complete login
                                        
                                        // SECURITY EVIDENCE 8: Session Regeneration (Prevent Session Fixation)
                                        session_regenerate_id(true);
                                        
                                        // Set session variables
                                        $_SESSION['user_id'] = $user['user_id'];
                                        $_SESSION['email'] = $user['email'];
                                        $_SESSION['full_name'] = $user['full_name'];
                                        $_SESSION['role'] = $user['role'];
                                        $_SESSION['last_activity'] = time();
                                        $_SESSION['created'] = time();
                                        
                                        // SECURITY EVIDENCE 9: Audit Logging
                                        logSecurityEvent('LOGIN_SUCCESS', "User logged in: $email");
                                        
                                        // Redirect to dashboard or original requested page
                                        $redirect = $_SESSION['redirect_after_login'] ?? 'dashboard.php';
                                        unset($_SESSION['redirect_after_login']);
                                        
                                        // Use JavaScript redirect to set sessionStorage first
                                        echo "<!DOCTYPE html><html><head><title>Login Successful</title></head><body>";
                                        echo "<script>";
                                        echo "sessionStorage.setItem('tab_logged_in', 'true');";
                                        echo "sessionStorage.setItem('login_time', Date.now());";
                                        echo "window.location.href = '" . htmlspecialchars($redirect) . "';";
                                        echo "</script>";
                                        echo "<p>Login successful! Redirecting...</p>";
                                        echo "</body></html>";
                                        exit();
                                    }
                                }
                                
                            } else {
                                // Failed login - increment failed attempts
                                $failed_attempts = $user['failed_login_attempts'] + 1;
                                
                                // SECURITY EVIDENCE 10: Account Lockout After 5 Failed Attempts
                                if ($failed_attempts >= 5) {
                                    $updateQuery = "UPDATE users 
                                                   SET failed_login_attempts = :attempts,
                                                       account_status = 'locked'
                                                   WHERE user_id = :user_id";
                                    $errors[] = "Account locked due to multiple failed login attempts. Please contact support.";
                                    logSecurityEvent('ACCOUNT_LOCKED', "Account locked after 5 failed attempts: $email");
                                } else {
                                    $updateQuery = "UPDATE users 
                                                   SET failed_login_attempts = :attempts 
                                                   WHERE user_id = :user_id";
                                    $errors[] = "Invalid email or password";
                                }
                                
                                $updateStmt = $db->prepare($updateQuery);
                                $updateStmt->execute([
                                    'attempts' => $failed_attempts,
                                    'user_id' => $user['user_id']
                                ]);
                                
                                logSecurityEvent('LOGIN_FAILED', "Failed login attempt for: $email (Attempt $failed_attempts/5)");
                            }
                        }
                    } else {
                        // User not found - generic error message (security best practice)
                        $errors[] = "Invalid email or password";
                        logSecurityEvent('LOGIN_FAILED', "Login attempt with non-existent email: $email");
                    }
                    
                } catch (PDOException $e) {
                    error_log("Login Error: " . $e->getMessage());
                    $errors[] = "An error occurred. Please try again.";
                }
                
                // Record rate limit attempt
                recordRateLimitAttempt($email);
            }
        }
    }
}

// Generate CSRF token
$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Lovejoy's Antique Evaluation</title>
    <?php 
    $recaptchaVersion = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v2';
    if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['login'] && $recaptchaVersion === 'v2'): 
    ?>
        <!-- reCAPTCHA v2 (Checkbox) -->
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <?php endif; ?>
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
            max-width: 450px;
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
        
        .btn:active {
            transform: translateY(0);
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
        
        .links {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
            font-size: 14px;
        }
        
        .links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .links a:hover {
            text-decoration: underline;
        }
        
        .register-link {
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 14px;
        }
        
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .register-link a:hover {
            text-decoration: underline;
        }
        
        .security-badge {
            background: #e8f5e9;
            border: 1px solid #4caf50;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 12px;
            color: #2e7d32;
            text-align: center;
        }
        
        .security-badge strong {
            display: block;
            margin-bottom: 5px;
        }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 12px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            font-size: 13px;
            color: #1565c0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏺 Lovejoy's Antiques</h1>
            <p>Login to your account</p>
        </div>
        
        <div class="security-badge">
            <strong>🔒 Secure Login</strong>
            Protected with brute-force prevention & encryption
        </div>
        
        <?php if (isset($_GET['error'])): ?>
            <?php if ($_GET['error'] === 'login_required'): ?>
                <div class="info-box">
                    Please login to access that page.
                </div>
            <?php elseif ($_GET['error'] === 'unauthorized'): ?>
                <div class="alert alert-danger">
                    You don't have permission to access that page.
                </div>
            <?php endif; ?>
        <?php endif; ?>
        
        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <strong>Login failed:</strong>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="" id="loginForm">
            <?php $recaptchaVersion = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v2'; ?>
            <!-- CSRF Token (Hidden Field) -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" 
                       id="email" 
                       name="email" 
                       placeholder="john.doe@example.com"
                       value="<?php echo htmlspecialchars($email ?? ''); ?>"
                       required
                       autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <div class="password-wrapper">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           placeholder="Enter your password"
                           required>
                    <button type="button" 
                            class="toggle-password" 
                            onclick="togglePasswordVisibility('password')"
                            aria-label="Toggle password visibility">
                        <span id="password-toggle-icon">👁️</span>
                    </button>
                </div>
            </div>
            
            <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['login'] && $recaptchaVersion === 'v2'): ?>
            <!-- reCAPTCHA v2 Checkbox -->
            <div class="form-group">
                <div class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>
            </div>
            <?php endif; ?>
            
            <button type="submit" class="btn">Login</button>
            
            <div class="links">
                <a href="forgot_password.php">Forgot Password?</a>
                <a href="index.php">Back to Home</a>
            </div>
        </form>
        
        <div class="register-link">
            Don't have an account? <a href="register.php">Register here</a>
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
        
        // Form validation and submission
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            
            // Basic validation
            if (!email || !password) {
                e.preventDefault();
                alert('Please enter both email and password');
                return false;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                e.preventDefault();
                alert('Please enter a valid email address');
                return false;
            }
            
            <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['login'] && $recaptchaVersion === 'v2'): ?>
            // v2: Check if checkbox is checked
            const recaptchaResponse = grecaptcha.getResponse();
            if (!recaptchaResponse) {
                e.preventDefault();
                alert('Please complete the reCAPTCHA verification!');
                return false;
            }
            // v2 submits normally with g-recaptcha-response
            <?php endif; ?>
        });
        
        // Mark this tab as logged in after successful login
        // This works with tab_check.js to enforce re-login on new tabs
        <?php if (isLoggedIn()): ?>
        sessionStorage.setItem('tab_logged_in', 'true');
        sessionStorage.setItem('login_time', Date.now());
        <?php endif; ?>
    </script>
</body>
</html>
