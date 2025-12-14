<?php
/**
 * Two-Factor Authentication Setup
 * Allows users to enable 2FA with Google Authenticator
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/2fa.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Require login
requireLogin();

$errors = [];
$success = '';
$step = 1; // Step 1: Generate QR, Step 2: Verify code, Step 3: Show backup codes

// Get current user
$user_id = $_SESSION['user_id'];
$email = $_SESSION['email'];
$role = $_SESSION['role'];

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Check if 2FA is already enabled
    $query = "SELECT two_factor_enabled, two_factor_secret FROM users WHERE user_id = :user_id";
    $stmt = $db->prepare($query);
    $stmt->execute(['user_id' => $user_id]);
    $user = $stmt->fetch();
    
    if ($user['two_factor_enabled']) {
        // Already enabled - redirect to disable page
        header('Location: disable_2fa.php');
        exit();
    }
    
    // Process form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
            $errors[] = "Invalid security token. Please try again.";
        } else {
            $action = $_POST['action'] ?? '';
            
            if ($action === 'generate') {
                // Step 1: Generate secret and QR code
                $secret = generate2FASecret();
                $_SESSION['2fa_temp_secret'] = $secret;
                $step = 2;
                
            } else if ($action === 'verify') {
                // Step 2: Verify the code entered by user
                $code = $_POST['code'] ?? '';
                $secret = $_SESSION['2fa_temp_secret'] ?? '';
                
                if (empty($secret)) {
                    $errors[] = "Session expired. Please start over.";
                    $step = 1;
                } else if (verify2FACode($secret, $code)) {
                    // Code verified! Enable 2FA and generate backup codes
                    
                    // Save secret to database
                    $updateQuery = "UPDATE users 
                                   SET two_factor_enabled = TRUE,
                                       two_factor_secret = :secret
                                   WHERE user_id = :user_id";
                    $updateStmt = $db->prepare($updateQuery);
                    $updateStmt->execute([
                        'secret' => $secret,
                        'user_id' => $user_id
                    ]);
                    
                    // Generate backup codes
                    $backupCodes = generate2FABackupCodes($user_id);
                    $_SESSION['2fa_backup_codes'] = $backupCodes;
                    
                    // Clean up temp secret
                    unset($_SESSION['2fa_temp_secret']);
                    
                    $step = 3;
                    $success = "Two-Factor Authentication enabled successfully!";
                    logSecurityEvent('2FA_ENABLED', "2FA enabled for user: $email");
                    
                } else {
                    $errors[] = "Invalid verification code. Please try again.";
                    $step = 2;
                }
            }
        }
    } else {
        // Initial page load - check if temp secret exists (user refreshed page)
        if (isset($_SESSION['2fa_temp_secret'])) {
            $step = 2;
        }
    }
    
} catch (PDOException $e) {
    error_log("2FA Setup Error: " . $e->getMessage());
    $errors[] = "An error occurred. Please try again.";
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enable Two-Factor Authentication - Lovejoy's Antique Evaluation</title>
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
            padding: 20px;
        }
        
        .container {
            max-width: 600px;
            margin: 50px auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            padding: 40px;
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
        
        .steps {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .step-item {
            flex: 1;
            text-align: center;
            padding: 10px;
            position: relative;
        }
        
        .step-item::after {
            content: '';
            position: absolute;
            top: 20px;
            right: -50%;
            width: 100%;
            height: 2px;
            background: #ddd;
            z-index: -1;
        }
        
        .step-item:last-child::after {
            display: none;
        }
        
        .step-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #ddd;
            color: #666;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .step-item.active .step-number {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .step-item.completed .step-number {
            background: #27ae60;
            color: white;
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
        
        .qr-container {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .qr-code {
            margin: 20px 0;
        }
        
        .secret-key {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            letter-spacing: 2px;
            word-break: break-all;
        }
        
        .instructions {
            background: #e8f4f8;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .instructions h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .instructions ol {
            margin-left: 20px;
        }
        
        .instructions li {
            color: #666;
            margin-bottom: 8px;
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
            font-size: 16px;
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
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .backup-codes {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .backup-codes h3 {
            color: #856404;
            margin-bottom: 15px;
        }
        
        .backup-codes-list {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin: 15px 0;
        }
        
        .backup-code {
            background: white;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            font-family: 'Courier New', monospace;
            font-size: 16px;
            letter-spacing: 2px;
        }
        
        .warning {
            color: #856404;
            font-weight: 600;
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Enable Two-Factor Authentication</h1>
        <p class="subtitle">Add an extra layer of security to your account</p>
        
        <!-- Progress Steps -->
        <div class="steps">
            <div class="step-item <?php echo ($step >= 1) ? 'active' : ''; ?> <?php echo ($step > 1) ? 'completed' : ''; ?>">
                <div class="step-number">1</div>
                <div>Setup</div>
            </div>
            <div class="step-item <?php echo ($step >= 2) ? 'active' : ''; ?> <?php echo ($step > 2) ? 'completed' : ''; ?>">
                <div class="step-number">2</div>
                <div>Verify</div>
            </div>
            <div class="step-item <?php echo ($step >= 3) ? 'active' : ''; ?>">
                <div class="step-number">3</div>
                <div>Backup Codes</div>
            </div>
        </div>
        
        <!-- Alerts -->
        <?php if (!empty($success)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <?php if (!empty($errors)): ?>
            <?php foreach ($errors as $error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>
        
        <!-- Step 1: Generate QR Code -->
        <?php if ($step === 1): ?>
            <div class="instructions">
                <h3>What is Two-Factor Authentication?</h3>
                <p style="color: #666; margin-bottom: 10px;">
                    Two-Factor Authentication (2FA) adds an extra layer of security to your account. 
                    When enabled, you'll need to enter a 6-digit code from your phone in addition to your password.
                </p>
                <p style="color: #666;">
                    You'll need a 2FA app like <strong>Google Authenticator</strong>, <strong>Authy</strong>, 
                    or <strong>Microsoft Authenticator</strong> installed on your phone.
                </p>
            </div>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <input type="hidden" name="action" value="generate">
                <button type="submit" class="btn btn-primary">Start Setup</button>
            </form>
            
        <!-- Step 2: Scan QR Code and Verify -->
        <?php elseif ($step === 2): ?>
            <?php 
            $secret = $_SESSION['2fa_temp_secret'];
            $qrCodeUrl = generate2FAQRCode($secret, $email, TWO_FACTOR_ISSUER);
            ?>
            
            <div class="instructions">
                <h3>Scan QR Code</h3>
                <ol>
                    <li>Open your authenticator app (Google Authenticator, Authy, etc.)</li>
                    <li>Tap "Add Account" or the "+" button</li>
                    <li>Scan the QR code below</li>
                    <li>Enter the 6-digit code shown in the app</li>
                </ol>
            </div>
            
            <div class="qr-container">
                <div class="qr-code">
                    <img src="<?php echo htmlspecialchars($qrCodeUrl); ?>" alt="2FA QR Code" style="max-width: 250px;">
                </div>
                
                <p style="color: #666; margin-bottom: 10px;">Can't scan? Enter this code manually:</p>
                <div class="secret-key"><?php echo htmlspecialchars($secret); ?></div>
            </div>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <input type="hidden" name="action" value="verify">
                
                <div class="form-group">
                    <label for="code">Enter 6-Digit Code</label>
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
                
                <button type="submit" class="btn btn-primary">Verify and Enable 2FA</button>
            </form>
            
        <!-- Step 3: Show Backup Codes -->
        <?php elseif ($step === 3): ?>
            <div class="backup-codes">
                <h3>⚠️ Save Your Backup Codes</h3>
                <p style="color: #856404; margin-bottom: 15px;">
                    These backup codes can be used to access your account if you lose your phone. 
                    Each code can only be used once.
                </p>
                
                <div class="backup-codes-list">
                    <?php foreach ($_SESSION['2fa_backup_codes'] as $code): ?>
                        <div class="backup-code"><?php echo htmlspecialchars($code); ?></div>
                    <?php endforeach; ?>
                </div>
                
                <p class="warning">
                    ⚠️ IMPORTANT: Print or save these codes in a secure location. 
                    They will not be shown again!
                </p>
            </div>
            
            <form method="POST" action="dashboard.php">
                <button type="submit" class="btn btn-primary">Continue to Dashboard</button>
            </form>
            
            <?php 
            // Clear backup codes from session after displaying
            unset($_SESSION['2fa_backup_codes']); 
            ?>
        <?php endif; ?>
        
        <div class="back-link">
            <a href="dashboard.php">← Back to Dashboard</a>
        </div>
    </div>
</body>
</html>
