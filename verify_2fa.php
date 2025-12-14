<?php
/**
 * Two-Factor Authentication Verification
 * Verifies 2FA code during login process
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/2fa.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Check if user is in 2FA verification stage
if (!isset($_SESSION['2fa_user_id'])) {
    header('Location: login.php');
    exit();
}

$errors = [];
$user_id = $_SESSION['2fa_user_id'];
$email = $_SESSION['2fa_email'] ?? '';
$show_qr_first = false;
$two_factor_secret = ''; // Store secret for QR code display

// Check if this is user's first login and get 2FA secret
try {
    $database = new Database();
    $db = $database->getConnection();
    
    $checkQuery = "SELECT last_login, two_factor_secret FROM users WHERE user_id = :user_id";
    $checkStmt = $db->prepare($checkQuery);
    $checkStmt->execute(['user_id' => $user_id]);
    $userData = $checkStmt->fetch();
    
    if ($userData) {
        // Store secret for QR code modal
        $two_factor_secret = $userData['two_factor_secret'];
        
        // If user has never logged in before (last_login is NULL), show QR code first
        if (is_null($userData['last_login'])) {
            $show_qr_first = true;
            $_SESSION['show_qr_code'] = true;
            $_SESSION['2fa_secret'] = $userData['two_factor_secret'];
        }
    }
} catch (PDOException $e) {
    error_log("2FA Check Error: " . $e->getMessage());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
    } else {
        $code = $_POST['code'] ?? '';
        $use_backup = isset($_POST['use_backup']) && $_POST['use_backup'] === '1';
        
        if (empty($code)) {
            $errors[] = "Please enter the verification code.";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // Get user's 2FA secret
                $query = "SELECT two_factor_secret FROM users WHERE user_id = :user_id";
                $stmt = $db->prepare($query);
                $stmt->execute(['user_id' => $user_id]);
                $user = $stmt->fetch();
                
                if (!$user) {
                    $errors[] = "Session expired. Please login again.";
                    unset($_SESSION['2fa_user_id'], $_SESSION['2fa_email']);
                } else {
                    $verified = false;
                    
                    if ($use_backup) {
                        // Verify backup code
                        $verified = verify2FABackupCode($user_id, $code);
                        if ($verified) {
                            logSecurityEvent('2FA_BACKUP_CODE_USED', "Backup code used for: $email");
                        }
                    } else {
                        // Verify TOTP code
                        $verified = verify2FACode($user['two_factor_secret'], $code);
                    }
                    
                    if ($verified) {
                        // 2FA verified! Complete the login
                        
                        // Get full user details
                        $userQuery = "SELECT user_id, email, full_name, role 
                                     FROM users WHERE user_id = :user_id";
                        $userStmt = $db->prepare($userQuery);
                        $userStmt->execute(['user_id' => $user_id]);
                        $userData = $userStmt->fetch();
                        
                        // Regenerate session
                        session_regenerate_id(true);
                        
                        // Set session variables
                        $_SESSION['user_id'] = $userData['user_id'];
                        $_SESSION['email'] = $userData['email'];
                        $_SESSION['full_name'] = $userData['full_name'];
                        $_SESSION['role'] = $userData['role'];
                        $_SESSION['last_activity'] = time();
                        $_SESSION['created'] = time();
                        
                        // Clear 2FA session variables
                        unset($_SESSION['2fa_user_id'], $_SESSION['2fa_email']);
                        
                        // Update last login
                        $updateQuery = "UPDATE users SET last_login = NOW() WHERE user_id = :user_id";
                        $updateStmt = $db->prepare($updateQuery);
                        $updateStmt->execute(['user_id' => $user_id]);
                        
                        logSecurityEvent('2FA_VERIFIED', "2FA verified for: $email");
                        
                        // Redirect to dashboard with sessionStorage setup
                        $redirect = $_SESSION['redirect_after_login'] ?? 'dashboard.php';
                        unset($_SESSION['redirect_after_login']);
                        
                        // Use JavaScript redirect to set sessionStorage first
                        echo "<!DOCTYPE html><html><head><title>2FA Verified</title></head><body>";
                        echo "<script>";
                        echo "sessionStorage.setItem('tab_logged_in', 'true');";
                        echo "sessionStorage.setItem('login_time', Date.now());";
                        echo "window.location.href = '" . htmlspecialchars($redirect) . "';";
                        echo "</script>";
                        echo "<p>2FA verification successful! Redirecting...</p>";
                        echo "</body></html>";
                        exit();
                        
                    } else {
                        $errors[] = "Invalid verification code. Please try again.";
                        logSecurityEvent('2FA_FAILED', "Failed 2FA verification for: $email");
                    }
                }
                
            } catch (PDOException $e) {
                error_log("2FA Verification Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
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
    <title>Two-Factor Authentication - Lovejoy's Antique Evaluation</title>
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
        
        .icon {
            font-size: 64px;
            text-align: center;
            margin-bottom: 20px;
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
        
        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
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
            font-size: 18px;
            text-align: center;
            letter-spacing: 5px;
            font-family: 'Courier New', monospace;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .help-text {
            color: #666;
            font-size: 14px;
            text-align: center;
            margin-top: 15px;
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
        
        .qr-link {
            text-align: right;
            margin-top: 15px;
        }
        
        .qr-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            cursor: pointer;
        }
        
        .qr-link a:hover {
            text-decoration: underline;
        }
        
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            animation: fadeIn 0.3s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 10px;
            max-width: 500px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            position: relative;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        .close-modal {
            position: absolute;
            right: 20px;
            top: 15px;
            font-size: 28px;
            font-weight: bold;
            color: #aaa;
            cursor: pointer;
            line-height: 1;
        }
        
        .close-modal:hover {
            color: #000;
        }
        
        .modal-header {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .qr-code-container {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .qr-code-container img {
            max-width: 100%;
            height: auto;
        }
        
        .secret-key {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: center;
        }
        
        .secret-key code {
            font-size: 16px;
            font-weight: bold;
            color: #1976d2;
            letter-spacing: 2px;
        }
    </style>
    <script>
        // Modal functions
        function openQRModal() {
            document.getElementById('qrModal').style.display = 'block';
        }
        
        function closeQRModal() {
            document.getElementById('qrModal').style.display = 'none';
        }
        
        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('qrModal');
            if (event.target == modal) {
                closeQRModal();
            }
        }
        
        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeQRModal();
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>Two-Factor Authentication</h1>
        <p class="subtitle">Enter the 6-digit code from your authenticator app</p>
        
        <?php if (!empty($errors)): ?>
            <?php foreach ($errors as $error): ?>
                <div class="alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>
        
        <!-- Normal 2FA Form -->
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            
            <div class="form-group">
                <label for="code">Verification Code</label>
                <input type="text" 
                       id="code" 
                       name="code" 
                       class="form-control" 
                       placeholder="000000"
                       maxlength="6"
                       pattern="[0-9]{6}"
                       required
                       autofocus>
            </div>
            
            <button type="submit" class="btn">Verify</button>
            
            <p class="help-text">
                Open your authenticator app and enter the 6-digit code shown for 
                <strong><?php echo htmlspecialchars($email); ?></strong>
            </p>
            
            <!-- QR Code link in bottom right -->
            <div class="qr-link">
                <a href="javascript:void(0);" onclick="openQRModal()">QR Code</a>
            </div>
        </form>
        
        <div class="back-link">
            <a href="login.php">← Back to Login</a>
        </div>
    </div>
    
    <!-- QR Code Modal -->
    <div id="qrModal" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeQRModal()">&times;</span>
            <div class="modal-header">
                <h2>🔐 Scan QR Code</h2>
                <p style="color: #666;">Use Google Authenticator to scan this code</p>
            </div>
            
            <?php
            if (!empty($two_factor_secret)) {
                // Use local QR code generation with all required parameters
                $qrUrl = "generate_qr.php?secret=" . urlencode($two_factor_secret) . 
                         "&email=" . urlencode($email) . 
                         "&issuer=" . urlencode(TWO_FACTOR_ISSUER);
                ?>
                
                <div class="qr-code-container">
                    <img src="<?php echo htmlspecialchars($qrUrl); ?>" 
                         alt="QR Code" 
                         style="max-width: 250px; height: auto;"
                         onerror="this.onerror=null; this.alt='Failed to load QR code'; this.style.display='none'; document.getElementById('qr-error').style.display='block';">
                    <div id="qr-error" style="display: none; color: #dc3545; padding: 20px;">
                        <p><strong>⚠️ QR Code Failed to Load</strong></p>
                        <p style="font-size: 12px;">Please use the manual key below instead.</p>
                    </div>
                </div>
                
                <div class="secret-key">
                    <p style="margin-bottom: 10px; color: #666;"><strong>Manual Setup Key:</strong></p>
                    <code><?php echo htmlspecialchars($two_factor_secret); ?></code>
                    <p style="margin-top: 10px; font-size: 12px; color: #999;">Enter this key in Google Authenticator if QR code doesn't work</p>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; font-size: 14px; color: #666;">
                    <strong>📱 Setup Instructions:</strong>
                    <ol style="margin: 10px 0 0 20px; text-align: left; line-height: 1.8;">
                        <li>Open <strong>Google Authenticator</strong> app</li>
                        <li>Tap <strong>"+"</strong> to add account</li>
                        <li>Choose <strong>"Scan QR code"</strong> (or "Enter a setup key")</li>
                        <li>Scan the code above or enter the key manually</li>
                        <li>Enter the 6-digit code shown to verify</li>
                    </ol>
                </div>
                
            <?php
            } else {
                echo '<p style="color: #dc3545; text-align: center;"><strong>❌ QR code not available</strong><br><br>No 2FA secret found. Please contact support.</p>';
            }
            ?>
        </div>
    </div>
</body>
</html>
