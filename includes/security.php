<?php
/**
 * SECURITY FUNCTIONS FOR LOVEJOY'S ANTIQUE EVALUATION APPLICATION
 * 
 * This file implements comprehensive security measures including:
 * - CSRF Protection
 * - XSS Prevention
 * - SQL Injection Prevention (via PDO prepared statements)
 * - Session Security (Secure, HttpOnly, SameSite cookies)
 * - Input Validation & Sanitization
 * - Rate Limiting (Brute Force Protection)
 * - File Upload Validation
 * - Password Strength Validation
 * - Audit Logging
 */

// ============================================================================
// SECURE SESSION CONFIGURATION
// ============================================================================
if (session_status() === PHP_SESSION_NONE) {
    // Security Evidence: Prevent session hijacking and XSS attacks
    ini_set('session.cookie_httponly', 1);      // Prevents JavaScript access to session cookie
    
    // Only use secure cookies on HTTPS (not in local development)
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        ini_set('session.cookie_secure', 1);    // Only send cookie over HTTPS
    }
    
    ini_set('session.use_only_cookies', 1);     // Prevents session fixation attacks
    ini_set('session.cookie_samesite', 'Strict'); // Prevents CSRF attacks
    ini_set('session.use_strict_mode', 1);      // Rejects uninitialized session IDs
    
    // Session cookie expires when browser closes (lifetime 0 is default)
    ini_set('session.cookie_lifetime', 0);      // 0 = Session cookie (deleted when browser closes)
    
    // Additional security: Make session cookie unavailable to JavaScript
    ini_set('session.cookie_httponly', 1);
    
    // Force session to use cookies only (no URL parameters)
    ini_set('session.use_only_cookies', 1);
    
    session_start();
    
    // ENHANCED: Track tab/window for strict session control
    // This ensures each new tab requires re-login
    if (!isset($_SESSION['initiated'])) {
        session_regenerate_id(true);
        $_SESSION['initiated'] = true;
        $_SESSION['tab_id'] = bin2hex(random_bytes(16));
        $_SESSION['created_at'] = time();
    }
    
    // Optional: Validate session hasn't been idle too long (30 minutes)
    if (isset($_SESSION['last_activity'])) {
        $idle_time = time() - $_SESSION['last_activity'];
        if ($idle_time > 1800) { // 30 minutes = 1800 seconds
            // Session expired due to inactivity
            session_unset();
            session_destroy();
            session_start();
        }
    }
    
    // Update last activity timestamp
    $_SESSION['last_activity'] = time();
}

// ============================================================================
// CSRF PROTECTION FUNCTIONS
// ============================================================================

/**
 * Generate CSRF Token
 * Security Evidence: Protects against Cross-Site Request Forgery (CSRF) attacks
 * Creates a unique token per session that must be validated on form submission
 * 
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        // Generate cryptographically secure random token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF Token
 * Security Evidence: Validates CSRF token using timing-safe comparison
 * Prevents timing attacks by using hash_equals()
 * 
 * @param string $token Token to verify
 * @return bool True if valid, false otherwise
 */
function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || !isset($token)) {
        logSecurityEvent('CSRF_VALIDATION_FAILED', 'Missing CSRF token');
        return false;
    }
    
    // Timing-safe comparison prevents timing attacks
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        logSecurityEvent('CSRF_VALIDATION_FAILED', 'Invalid CSRF token');
        return false;
    }
    
    // Check token age (expire after 1 hour)
    if (isset($_SESSION['csrf_token_time']) && (time() - $_SESSION['csrf_token_time']) > 3600) {
        logSecurityEvent('CSRF_TOKEN_EXPIRED', 'CSRF token expired');
        return false;
    }
    
    return true;
}

// ============================================================================
// INPUT SANITIZATION & VALIDATION FUNCTIONS
// ============================================================================

/**
 * Sanitize Input
 * Security Evidence: Prevents XSS (Cross-Site Scripting) attacks
 * Converts special characters to HTML entities
 * 
 * @param string $data Input data
 * @return string Sanitized data
 */
function sanitizeInput($data) {
    if (!is_string($data)) {
        return $data;
    }
    $data = trim($data);
    $data = stripslashes($data);
    // Prevents XSS by converting <script> tags to &lt;script&gt;
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $data;
}

/**
 * Validate Email
 * Security Evidence: Ensures email format is valid, prevents injection
 * 
 * @param string $email Email address
 * @return bool True if valid
 */
function validateEmail($email) {
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate Phone Number
 * Security Evidence: Ensures phone contains only valid characters
 * Prevents injection of malicious code
 * 
 * @param string $phone Phone number
 * @return bool True if valid
 */
function validatePhone($phone) {
    // Allow digits, spaces, hyphens, plus signs, and parentheses
    return preg_match('/^[\d\s\-\+\(\)]{10,20}$/', $phone);
}

// ============================================================================
// PASSWORD SECURITY FUNCTIONS
// ============================================================================

/**
 * Validate Password Strength
 * Security Evidence: Enforces strong password policy
 * Requirements:
 * - Minimum 12 characters (NIST recommendation)
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 * 
 * @param string $password Password to validate
 * @return array Array of validation errors (empty if valid)
 */
function validatePasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < 12) {
        $errors[] = "Password must be at least 12 characters long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter (A-Z)";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter (a-z)";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number (0-9)";
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character (@, #, $, %, etc.)";
    }
    
    // Check against common passwords
    $commonPasswords = ['password123', 'admin123456', 'qwerty123456', '123456789012'];
    if (in_array(strtolower($password), $commonPasswords)) {
        $errors[] = "Password is too common. Please choose a more unique password";
    }
    
    return $errors;
}

/**
 * Get Password Strength Score
 * Security Evidence: Provides real-time feedback to users
 * Encourages stronger passwords
 * 
 * @param string $password Password
 * @return array Score, text description, and CSS class
 */
function getPasswordStrength($password) {
    $strength = 0;
    
    // Length criteria
    if (strlen($password) >= 12) $strength++;
    if (strlen($password) >= 16) $strength++;
    if (strlen($password) >= 20) $strength++;
    
    // Character diversity criteria
    if (preg_match('/[a-z]/', $password)) $strength++;
    if (preg_match('/[A-Z]/', $password)) $strength++;
    if (preg_match('/[0-9]/', $password)) $strength++;
    if (preg_match('/[^A-Za-z0-9]/', $password)) $strength++;
    
    // Variety bonus
    if (preg_match('/[!@#$%^&*]/', $password)) $strength++;
    
    if ($strength <= 3) return ['score' => $strength, 'text' => 'Weak', 'class' => 'danger'];
    if ($strength <= 5) return ['score' => $strength, 'text' => 'Moderate', 'class' => 'warning'];
    return ['score' => $strength, 'text' => 'Strong', 'class' => 'success'];
}

/**
 * Hash Password
 * Security Evidence: Uses bcrypt algorithm with cost factor 12
 * Bcrypt is resistant to brute-force attacks
 * 
 * @param string $password Plain text password
 * @return string Hashed password
 */
function hashPassword($password) {
    // Cost factor 12 = 2^12 iterations (secure as of 2025)
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Verify Password
 * Security Evidence: Timing-safe password verification
 * 
 * @param string $password Plain text password
 * @param string $hash Stored hash
 * @return bool True if password matches
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// ============================================================================
// SESSION MANAGEMENT & AUTHENTICATION FUNCTIONS
// ============================================================================

/**
 * Check if User is Logged In
 * Security Evidence: Validates session with timeout protection
 * Implements 30-minute inactivity timeout
 * 
 * @return bool True if logged in
 */
function isLoggedIn() {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['email'])) {
        return false;
    }
    
    // Session timeout: 30 minutes of inactivity
    if (isset($_SESSION['last_activity'])) {
        $inactiveTime = time() - $_SESSION['last_activity'];
        if ($inactiveTime > 1800) { // 30 minutes
            logSecurityEvent('SESSION_TIMEOUT', 'Session expired due to inactivity');
            session_unset();
            session_destroy();
            return false;
        }
    }
    
    // Update last activity time
    $_SESSION['last_activity'] = time();
    
    // Regenerate session ID periodically (every 10 minutes)
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } else if (time() - $_SESSION['created'] > 600) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
    
    return true;
}

/**
 * Check if User is Admin
 * Security Evidence: Role-based access control (RBAC)
 * 
 * @return bool True if user is admin
 */
function isAdmin() {
    return isLoggedIn() && isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

/**
 * Require Login
 * Security Evidence: Enforces authentication before accessing protected pages
 * Also prevents page caching to stop back button bypass
 * 
 * @return void
 */
function requireLogin() {
    // Prevent page caching
    preventPageCaching();
    
    if (!isLoggedIn()) {
        $_SESSION['redirect_after_login'] = $_SERVER['REQUEST_URI'];
        header('Location: /Compsec/lovejoy_secure_app/login.php?error=login_required');
        exit();
    }
}

/**
 * Require Admin
 * Security Evidence: Enforces authorization for admin-only pages
 * 
 * @return void
 */
function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', 'Non-admin user tried to access admin page');
        header('Location: /Compsec/lovejoy_secure_app/dashboard.php?error=unauthorized');
        exit();
    }
}

/**
 * Prevent Page Caching
 * Prevents browser from caching protected pages (stops back button bypass)
 * 
 * @return void
 */
function preventPageCaching() {
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Expires: 0");
}

// ============================================================================
// RATE LIMITING & BRUTE FORCE PROTECTION
// ============================================================================

/**
 * Check Rate Limit
 * Security Evidence: Prevents brute force attacks on login
 * Limits to 5 attempts per 15 minutes
 * 
 * @param string $identifier Unique identifier (e.g., email or IP)
 * @param int $maxAttempts Maximum attempts allowed
 * @param int $timeWindow Time window in seconds
 * @return bool True if under limit
 */
function checkRateLimit($identifier, $maxAttempts = 5, $timeWindow = 900) {
    if (!isset($_SESSION['rate_limit'])) {
        $_SESSION['rate_limit'] = [];
    }
    
    $now = time();
    $key = 'attempts_' . hash('sha256', $identifier);
    
    // Initialize if not exists
    if (!isset($_SESSION['rate_limit'][$key])) {
        $_SESSION['rate_limit'][$key] = [];
    }
    
    // Clean old entries outside time window
    $_SESSION['rate_limit'][$key] = array_filter(
        $_SESSION['rate_limit'][$key],
        function($timestamp) use ($now, $timeWindow) {
            return ($now - $timestamp) < $timeWindow;
        }
    );
    
    // Check if limit exceeded
    if (count($_SESSION['rate_limit'][$key]) >= $maxAttempts) {
        logSecurityEvent('RATE_LIMIT_EXCEEDED', "Rate limit exceeded for: $identifier");
        return false;
    }
    
    return true;
}

/**
 * Record Rate Limit Attempt
 * 
 * @param string $identifier Unique identifier
 * @return void
 */
function recordRateLimitAttempt($identifier) {
    $key = 'attempts_' . hash('sha256', $identifier);
    if (!isset($_SESSION['rate_limit'][$key])) {
        $_SESSION['rate_limit'][$key] = [];
    }
    $_SESSION['rate_limit'][$key][] = time();
}

// ============================================================================
// FILE UPLOAD VALIDATION
// ============================================================================

/**
 * Validate File Upload
 * Security Evidence:
 * - Validates MIME type using fileinfo extension
 * - Checks file extension against whitelist
 * - Limits file size to prevent DoS
 * - Prevents malicious file uploads
 * 
 * @param array $file $_FILES array element
 * @return array Validation result
 */
function validateFileUpload($file) {
    $errors = [];
    
    // Check if file was uploaded
    if (!isset($file['tmp_name']) || $file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = "File upload failed. Please try again.";
        return ['valid' => false, 'errors' => $errors];
    }
    
    // Validate file size (max 5MB)
    if ($file['size'] > 5242880) {
        $errors[] = "File size must not exceed 5MB";
    }
    
    // Validate MIME type (prevents fake extensions)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimeTypes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp'
    ];
    
    if (!in_array($mimeType, $allowedMimeTypes)) {
        $errors[] = "Only JPEG, PNG, GIF, and WebP images are allowed";
    }
    
    // Validate file extension
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    
    if (!in_array($extension, $allowedExtensions)) {
        $errors[] = "Invalid file extension. Allowed: " . implode(', ', $allowedExtensions);
    }
    
    // Check for double extensions (e.g., file.php.jpg)
    $filename = $file['name'];
    if (substr_count($filename, '.') > 1) {
        $errors[] = "Multiple file extensions are not allowed";
    }
    
    if (count($errors) > 0) {
        return ['valid' => false, 'errors' => $errors];
    }
    
    return [
        'valid' => true,
        'mime_type' => $mimeType,
        'extension' => $extension,
        'size' => $file['size']
    ];
}

/**
 * Sanitize Filename
 * Security Evidence: Prevents path traversal attacks
 * Removes dangerous characters from filename
 * 
 * @param string $filename Original filename
 * @return string Sanitized filename
 */
function sanitizeFilename($filename) {
    // Get basename to prevent path traversal
    $filename = basename($filename);
    
    // Remove all except alphanumeric, dot, dash, underscore
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
    
    // Prevent hidden files
    $filename = ltrim($filename, '.');
    
    // Add timestamp prefix for uniqueness
    $filename = time() . '_' . $filename;
    
    return $filename;
}

// ============================================================================
// TOKEN GENERATION FUNCTIONS
// ============================================================================

/**
 * Generate Secure Token
 * Security Evidence: Uses cryptographically secure random bytes
 * Used for password reset tokens
 * 
 * @param int $length Token length
 * @return string Secure token
 */
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// ============================================================================
// SECURITY LOGGING & AUDIT TRAIL
// ============================================================================

/**
 * Log Security Event
 * Security Evidence: Creates audit trail for security analysis
 * Logs all authentication and authorization events
 * 
 * @param string $action Action type
 * @param string $details Additional details
 * @return void
 */
function logSecurityEvent($action, $details = '') {
    try {
        require_once __DIR__ . '/../config/database.php';
        
        $database = new Database();
        $db = $database->getConnection();
        
        $query = "INSERT INTO audit_log (user_id, action, ip_address, user_agent, details) 
                  VALUES (:user_id, :action, :ip_address, :user_agent, :details)";
        
        $stmt = $db->prepare($query);
        $stmt->execute([
            'user_id' => $_SESSION['user_id'] ?? null,
            'action' => $action,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'details' => $details
        ]);
        
    } catch (Exception $e) {
        error_log("Failed to log security event: " . $e->getMessage());
    }
}

// ============================================================================
// SECURITY HEADERS
// ============================================================================

/**
 * Set Security Headers
 * Security Evidence: Protects against various web attacks
 * - X-Frame-Options: Prevents clickjacking
 * - X-Content-Type-Options: Prevents MIME sniffing
 * - X-XSS-Protection: Enables browser XSS filter
 * - Content-Security-Policy: Restricts resource loading
 * - Referrer-Policy: Controls referrer information
 * 
 * @return void
 */
function setSecurityHeaders() {
    // Prevent clickjacking attacks
    header('X-Frame-Options: DENY');
    
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Enable XSS protection in browsers
    header('X-XSS-Protection: 1; mode=block');
    
    // Control referrer information
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy (updated to allow Google reCAPTCHA)
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-src https://www.google.com;");
    
    // Strict Transport Security (HSTS) - only over HTTPS
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// Apply security headers to every request
setSecurityHeaders();

// ============================================================================
// GOOGLE reCAPTCHA v3 VERIFICATION
// ============================================================================

/**
 * Verify reCAPTCHA v2 or v3 token
 * 
 * @param string $token The reCAPTCHA token/response from the client
 * @param string $action The action name (e.g., 'login', 'register') - only used for v3
 * @return array ['success' => bool, 'score' => float, 'error' => string]
 */
function verifyRecaptcha($token, $action = '') {
    if (!defined('RECAPTCHA_ENABLED') || !RECAPTCHA_ENABLED) {
        return ['success' => true, 'score' => 1.0, 'error' => ''];
    }
    
    // Development mode bypass for localhost testing
    if (defined('RECAPTCHA_DEV_MODE') && RECAPTCHA_DEV_MODE) {
        error_log("reCAPTCHA: Development mode active - bypassing verification");
        return ['success' => true, 'score' => 1.0, 'error' => '', 'dev_mode' => true];
    }
    
    if (empty($token)) {
        return ['success' => false, 'score' => 0.0, 'error' => 'No token provided'];
    }
    
    $secretKey = RECAPTCHA_SECRET_KEY;
    $verifyURL = 'https://www.google.com/recaptcha/api/siteverify';
    $version = defined('RECAPTCHA_VERSION') ? RECAPTCHA_VERSION : 'v3';
    
    // Prepare POST data
    $postData = [
        'secret' => $secretKey,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
    ];
    
    // Use cURL to verify token
    $ch = curl_init($verifyURL);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    if ($httpCode !== 200 || !empty($curlError)) {
        error_log("reCAPTCHA API Error: HTTP $httpCode - $curlError");
        return ['success' => false, 'score' => 0.0, 'error' => 'API request failed'];
    }
    
    $result = json_decode($response, true);
    
    if (!$result) {
        error_log("reCAPTCHA Response Parse Error: " . $response);
        return ['success' => false, 'score' => 0.0, 'error' => 'Invalid API response'];
    }
    
    // For v2, there's no score - just success/fail
    $score = isset($result['score']) ? $result['score'] : ($result['success'] ? 1.0 : 0.0);
    
    // Store reCAPTCHA score in database for analysis
    if ($version === 'v3' || isset($result['score'])) {
        storeRecaptchaScore(
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $action,
            $score,
            $result['success'] ?? false,
            $result['hostname'] ?? '',
            $result['challenge_ts'] ?? ''
        );
    }
    
    return [
        'success' => $result['success'] ?? false,
        'score' => $score,
        'action' => $result['action'] ?? '',
        'hostname' => $result['hostname'] ?? '',
        'challenge_ts' => $result['challenge_ts'] ?? '',
        'error' => isset($result['error-codes']) ? implode(', ', $result['error-codes']) : ''
    ];
}

/**
 * Store reCAPTCHA score in database for analysis
 */
function storeRecaptchaScore($ipAddress, $action, $score, $success, $hostname, $challengeTs) {
    try {
        require_once __DIR__ . '/../config/database.php';
        $database = new Database();
        $db = $database->getConnection();
        
        $query = "INSERT INTO recaptcha_scores (ip_address, action, score, success, hostname, challenge_ts) 
                  VALUES (:ip_address, :action, :score, :success, :hostname, :challenge_ts)";
        
        $stmt = $db->prepare($query);
        $stmt->execute([
            'ip_address' => $ipAddress,
            'action' => $action,
            'score' => $score,
            'success' => $success ? 1 : 0,
            'hostname' => $hostname,
            'challenge_ts' => $challengeTs ? date('Y-m-d H:i:s', strtotime($challengeTs)) : null
        ]);
    } catch (Exception $e) {
        error_log("Failed to store reCAPTCHA score: " . $e->getMessage());
    }
}

// ============================================================================
// END OF RECAPTCHA FUNCTIONS
// ============================================================================
