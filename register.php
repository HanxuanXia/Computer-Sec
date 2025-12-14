<?php
/**
 * TASK 1: SECURE USER REGISTRATION (5 marks - Code Quality)
 * 
 * Security Features Implemented:
 * 1. CSRF Protection - Validates CSRF token on form submission
 * 2. Input Validation & Sanitization - Prevents XSS attacks
 * 3. Strong Password Policy - Enforces 12+ chars with complexity requirements
 * 4. SQL Injection Prevention - Uses PDO prepared statements
 * 5. Email Uniqueness Check - Prevents duplicate accounts
 * 6. Rate Limiting - Prevents automated registration abuse
 * 7. Password Hashing - Uses bcrypt with cost factor 12
 * 8. Audit Logging - Tracks all registration attempts
 * 9. Email Verification - Sends verification link to user's email
 * 10. Google reCAPTCHA v3 - Prevents bot registrations
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/email.php';
require_once __DIR__ . '/includes/email_verification.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Initialize variables
$errors = [];
$success = '';

// Process registration form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY EVIDENCE 1: CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('REGISTRATION_CSRF_FAILED', 'Invalid CSRF token on registration');
    } else {
        // SECURITY EVIDENCE 2: Google reCAPTCHA Verification
        if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register']) {
            $version = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v3';
            
            if ($version === 'v2') {
                // v2 Checkbox - response comes from g-recaptcha-response
                $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';
            } else {
                // v3 Invisible - token from hidden field
                $recaptchaResponse = $_POST['recaptcha_token'] ?? '';
            }
            
            $recaptchaResult = verifyRecaptcha($recaptchaResponse, 'register');
            
            if (!$recaptchaResult['success']) {
                $errors[] = "reCAPTCHA verification failed. Please try again.";
                logSecurityEvent('REGISTRATION_RECAPTCHA_FAILED', 'reCAPTCHA failed: ' . $recaptchaResult['error']);
            } else if ($version === 'v3' && $recaptchaResult['score'] < RECAPTCHA_SCORE_THRESHOLD) {
                $errors[] = "Suspicious activity detected. Please try again later.";
                logSecurityEvent('REGISTRATION_LOW_RECAPTCHA_SCORE', "Low score: " . $recaptchaResult['score']);
            }
        }
        
        // SECURITY EVIDENCE 3: Input Sanitization (XSS Prevention)
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $full_name = sanitizeInput($_POST['full_name'] ?? '');
        $phone_number = sanitizeInput($_POST['phone_number'] ?? '');
        
        // SECURITY EVIDENCE 4: Input Validation
        if (empty($email) || empty($password) || empty($full_name) || empty($phone_number)) {
            $errors[] = "All fields are required";
        }
        
        if (!validateEmail($email)) {
            $errors[] = "Invalid email address format";
        }
        
        if (!validatePhone($phone_number)) {
            $errors[] = "Invalid phone number format. Use format: +XX-XXX-XXX-XXXX";
        }
        
        if ($password !== $confirm_password) {
            $errors[] = "Passwords do not match";
        }
        
        // SECURITY EVIDENCE 5: Strong Password Policy
        $passwordErrors = validatePasswordStrength($password);
        if (!empty($passwordErrors)) {
            $errors = array_merge($errors, $passwordErrors);
        }
        
        // SECURITY EVIDENCE 6: Rate Limiting (Prevent Abuse)
        if (!checkRateLimit($email, 3, 300)) { // 3 attempts per 5 minutes
            $errors[] = "Too many registration attempts. Please try again later.";
            logSecurityEvent('REGISTRATION_RATE_LIMIT', "Rate limit exceeded for: $email");
        }
        
        // If no errors, proceed with registration
        if (empty($errors)) {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // SECURITY EVIDENCE 7: Check for duplicate email
                $checkQuery = "SELECT user_id FROM users WHERE email = :email";
                $checkStmt = $db->prepare($checkQuery);
                $checkStmt->execute(['email' => $email]);
                
                if ($checkStmt->rowCount() > 0) {
                    $errors[] = "An account with this email already exists";
                    logSecurityEvent('REGISTRATION_DUPLICATE_EMAIL', "Attempted registration with existing email: $email");
                } else {
                    // SECURITY EVIDENCE 8: Password Hashing (Bcrypt with cost 12)
                    $password_hash = hashPassword($password);
                    
                    // Set account status based on email verification requirement
                    $account_status = 'pending'; // Account pending until email verified
                    $email_verified = 0; // Not verified yet
                    
                    // Generate 2FA secret for new user (if 2FA is enabled)
                    $two_factor_secret = null;
                    $two_factor_enabled = 0;
                    if (defined('TWO_FACTOR_ENABLED') && TWO_FACTOR_ENABLED) {
                        require_once __DIR__ . '/includes/2fa.php';
                        $two_factor_secret = generate2FASecret();
                        $two_factor_enabled = 1; // Enable 2FA for all new users
                        logSecurityEvent('2FA_AUTO_ENABLED', "2FA automatically enabled for new user: $email");
                    }
                    
                    // SECURITY EVIDENCE 9: SQL Injection Prevention (Prepared Statements)
                    $insertQuery = "INSERT INTO users (email, password_hash, full_name, phone_number, role, account_status, 
                                                       email_verified, two_factor_enabled, two_factor_secret) 
                                    VALUES (:email, :password_hash, :full_name, :phone_number, 'customer', :account_status,
                                           :email_verified, :two_factor_enabled, :two_factor_secret)";
                    
                    $insertStmt = $db->prepare($insertQuery);
                    $result = $insertStmt->execute([
                        'email' => $email,
                        'password_hash' => $password_hash,
                        'full_name' => $full_name,
                        'phone_number' => $phone_number,
                        'account_status' => $account_status,
                        'email_verified' => $email_verified,
                        'two_factor_enabled' => $two_factor_enabled,
                        'two_factor_secret' => $two_factor_secret
                    ]);
                    
                    if ($result) {
                        // Get the new user ID
                        $new_user_id = $db->lastInsertId();
                        
                        // SECURITY EVIDENCE 10: Generate and send 6-digit verification code
                        $verification_code = generateVerificationCode();
                        
                        // Store verification code in database
                        if (storeVerificationCode($email, $verification_code, $new_user_id)) {
                            // Send verification code via email
                            $emailSent = sendVerificationCodeEmail($email, $full_name, $verification_code);
                            
                            if ($emailSent) {
                                // Store email in session for verification page
                                $_SESSION['pending_verification_email'] = $email;
                                
                                // SECURITY EVIDENCE 11: Audit Logging
                                logSecurityEvent('USER_REGISTERED', "New user registered: $email - Verification code sent");
                                
                                // Redirect to verification page
                                header('Location: verify_registration_code.php');
                                exit;
                                exit;
                            } else {
                                $errors[] = "Registration successful but failed to send verification email. Please contact support.";
                                logSecurityEvent('VERIFICATION_EMAIL_FAILED', "Failed to send verification code to: $email");
                            }
                        } else {
                            $errors[] = "Registration successful but failed to generate verification code. Please contact support.";
                            logSecurityEvent('VERIFICATION_CODE_FAILED', "Failed to store verification code for: $email");
                        }
                    } else {
                        $errors[] = "Registration failed. Please try again.";
                    }
                }
                
            } catch (PDOException $e) {
                error_log("Registration Error: " . $e->getMessage());
                $errors[] = "An error occurred during registration. Please try again.";
            }
            
            // Record rate limit attempt
            recordRateLimitAttempt($email);
        }
    }
}

// Generate CSRF token for form
$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Lovejoy's Antique Evaluation</title>
    <?php 
    $recaptchaVersion = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v3';
    if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register']): 
    ?>
        <?php if ($recaptchaVersion === 'v2'): ?>
            <!-- reCAPTCHA v2 (Checkbox) -->
            <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        <?php else: ?>
            <!-- reCAPTCHA v3 (Invisible) -->
            <script src="https://www.google.com/recaptcha/api.js?render=<?php echo RECAPTCHA_SITE_KEY; ?>" async defer></script>
            <style>
                /* Show reCAPTCHA badge */
                .grecaptcha-badge { 
                    visibility: visible !important;
                    opacity: 1 !important;
                }
                
                /* Loading indicator */
                .btn.loading {
                    position: relative;
                    pointer-events: none;
                    opacity: 0.7;
                }
                
                .btn.loading::after {
                    content: "";
                    position: absolute;
                    width: 16px;
                    height: 16px;
                    top: 50%;
                    left: 50%;
                    margin-left: -8px;
                    margin-top: -8px;
                    border: 2px solid #ffffff;
                    border-radius: 50%;
                    border-top-color: transparent;
                    animation: spinner 0.6s linear infinite;
                }
                
                @keyframes spinner {
                    to { transform: rotate(360deg); }
                }
            </style>
        <?php endif; ?>
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
        
        input[type="text"],
        input[type="email"],
        input[type="password"],
        input[type="tel"] {
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
        
        .password-strength {
            margin-top: 8px;
            height: 5px;
            background: #e0e0e0;
            border-radius: 3px;
            overflow: hidden;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background 0.3s;
        }
        
        .password-strength-bar.danger {
            background: #e74c3c;
        }
        
        .password-strength-bar.warning {
            background: #f39c12;
        }
        
        .password-strength-bar.success {
            background: #27ae60;
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
            color: #333;
            font-size: 13px;
            margin-bottom: 8px;
        }
        
        .password-requirements ul {
            list-style: none;
            padding-left: 0;
        }
        
        .password-requirements li {
            color: #666;
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
        
        .login-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .login-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .login-link a:hover {
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏺 Lovejoy's Antiques</h1>
            <p>Create your account to request evaluations</p>
        </div>
        
        <div class="security-badge">
            <strong>🔒 Secure Registration</strong>
            Your data is protected with enterprise-grade security
        </div>
        
        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
            <div class="login-link" style="margin-top: 30px;">
                <strong>Ready to get started?</strong><br>
                <a href="login.php" style="font-size: 16px;">← Go to Login Page</a>
            </div>
        <?php else: ?>
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <strong>Please correct the following errors:</strong>
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
        
            <form method="POST" action="" id="registrationForm">
                <!-- CSRF Token (Hidden Field) -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            
            <!-- reCAPTCHA Token (Hidden Field) -->
            <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register']): ?>
            <input type="hidden" name="recaptcha_token" id="recaptchaToken">
            <?php endif; ?>
            
            <div class="form-group">
                <label for="email">Email Address *</label>
                <input type="email" 
                       id="email" 
                       name="email" 
                       placeholder="john.doe@example.com"
                       value="<?php echo htmlspecialchars($email ?? ''); ?>"
                       required>
            </div>
            
            <div class="form-group">
                <label for="full_name">Full Name *</label>
                <input type="text" 
                       id="full_name" 
                       name="full_name" 
                       placeholder="John Doe"
                       value="<?php echo htmlspecialchars($full_name ?? ''); ?>"
                       required>
            </div>
            
            <div class="form-group">
                <label for="phone_number">Phone Number *</label>
                <input type="tel" 
                       id="phone_number" 
                       name="phone_number" 
                       placeholder="+44-20-1234-5678"
                       value="<?php echo htmlspecialchars($phone_number ?? ''); ?>"
                       required>
            </div>
            
            <div class="form-group">
                <label for="password">Password *</label>
                <div class="password-wrapper">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           placeholder="Enter a strong password"
                           required>
                    <button type="button" 
                            class="toggle-password" 
                            onclick="togglePasswordVisibility('password')"
                            aria-label="Toggle password visibility">
                        <span id="password-toggle-icon">👁️</span>
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
                <label for="confirm_password">Confirm Password *</label>
                <div class="password-wrapper">
                    <input type="password" 
                           id="confirm_password" 
                           name="confirm_password" 
                           placeholder="Re-enter your password"
                           required>
                    <button type="button" 
                            class="toggle-password" 
                            onclick="togglePasswordVisibility('confirm_password')"
                            aria-label="Toggle confirm password visibility">
                        <span id="confirm_password-toggle-icon">👁️</span>
                    </button>
                </div>
            </div>
            
            <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register'] && $recaptchaVersion === 'v2'): ?>
            <!-- reCAPTCHA v2 Checkbox -->
            <div class="form-group" style="margin: 25px 0;">
                <div class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>
            </div>
            <?php endif; ?>
            
            <button type="submit" class="btn">Create Account</button>
        </form>
        
        <div class="login-link">
            Already have an account? <a href="login.php">Login here</a>
        </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Only run if registration form exists (not on success screen)
        const registrationForm = document.getElementById('registrationForm');
        
        if (registrationForm) {
            // Toggle password visibility function
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
            
            // Make the function globally accessible
            window.togglePasswordVisibility = togglePasswordVisibility;
            
            // Real-time password strength indicator
            document.getElementById('password').addEventListener('input', function(e) {
            const password = e.target.value;
            let strength = 0;
            
            if (password.length >= 12) strength++;
            if (password.length >= 16) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;
            if (password.length >= 20) strength++;
            
            const bar = document.getElementById('strengthBar');
            const text = document.getElementById('strengthText');
            
            if (strength <= 2) {
                bar.style.width = '33%';
                bar.className = 'password-strength-bar danger';
                text.textContent = 'Weak Password';
                text.style.color = '#e74c3c';
            } else if (strength <= 4) {
                bar.style.width = '66%';
                bar.className = 'password-strength-bar warning';
                text.textContent = 'Moderate Password';
                text.style.color = '#f39c12';
            } else {
                bar.style.width = '100%';
                bar.className = 'password-strength-bar success';
                text.textContent = 'Strong Password';
                text.style.color = '#27ae60';
            }
        });
        
        <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register']): ?>
        // Global flag to track reCAPTCHA status
        let recaptchaReady = false;
        
        // Wait for reCAPTCHA to load
        function waitForRecaptcha() {
            return new Promise((resolve, reject) => {
                let attempts = 0;
                const maxAttempts = 50;
                
                const checkInterval = setInterval(function() {
                    attempts++;
                    
                    if (typeof grecaptcha !== 'undefined' && grecaptcha.ready) {
                        clearInterval(checkInterval);
                        grecaptcha.ready(function() {
                            recaptchaReady = true;
                            console.log('✓ reCAPTCHA loaded and ready');
                            resolve();
                        });
                    } else if (attempts >= maxAttempts) {
                        clearInterval(checkInterval);
                        console.error('❌ reCAPTCHA failed to load');
                        reject(new Error('reCAPTCHA timeout'));
                    }
                }, 100);
            });
        }
        
        // Start waiting for reCAPTCHA
        document.addEventListener('DOMContentLoaded', function() {
            waitForRecaptcha().catch(function(error) {
                console.error('reCAPTCHA loading error:', error);
            });
        });
        <?php endif; ?>
        
        // Form validation before submit
        document.getElementById('registrationForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
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
            
            <?php if (RECAPTCHA_ENABLED && RECAPTCHA_ACTIONS['register']): ?>
            <?php if ($recaptchaVersion === 'v2'): ?>
            // v2: Check if checkbox is checked
            const recaptchaResponse = grecaptcha.getResponse();
            if (!recaptchaResponse) {
                e.preventDefault();
                alert('Please complete the reCAPTCHA verification!');
                return false;
            }
            // v2 submits normally with g-recaptcha-response
            <?php else: ?>
            // v3: Execute invisible reCAPTCHA
            e.preventDefault();
            
            const submitBtn = e.target.querySelector('.btn[type="submit"]');
            
            // Show loading state
            submitBtn.classList.add('loading');
            submitBtn.disabled = true;
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Verifying...';
            
            // Ensure reCAPTCHA is ready
            if (!recaptchaReady) {
                console.log('Waiting for reCAPTCHA...');
                waitForRecaptcha()
                    .then(function() {
                        executeRecaptchaAndSubmit();
                    })
                    .catch(function(error) {
                        alert('Security verification unavailable. Please check your internet connection and try again.');
                        submitBtn.classList.remove('loading');
                        submitBtn.disabled = false;
                        submitBtn.textContent = originalText;
                    });
            } else {
                executeRecaptchaAndSubmit();
            }
            
            function executeRecaptchaAndSubmit() {
                grecaptcha.execute('<?php echo RECAPTCHA_SITE_KEY; ?>', {action: 'register'})
                    .then(function(token) {
                        console.log('✓ reCAPTCHA token received');
                        document.getElementById('recaptchaToken').value = token;
                        e.target.submit();
                    })
                    .catch(function(error) {
                        console.error('reCAPTCHA error:', error);
                        alert('Security verification failed. Please try again.');
                        submitBtn.classList.remove('loading');
                        submitBtn.disabled = false;
                        submitBtn.textContent = originalText;
                    });
            }
            <?php endif; ?>
            <?php endif; ?>
        });
        
        } // End of if (registrationForm) check
    </script>
</body>
</html>
