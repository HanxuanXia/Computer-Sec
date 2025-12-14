<?php
/**
 * Show Current User's 2FA QR Code
 * Displays QR code for scanning, even if 2FA is already enabled
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/2fa.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Require login
requireLogin();

$user_id = $_SESSION['user_id'];
$email = $_SESSION['email'];
$full_name = $_SESSION['full_name'];

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Get user's 2FA secret
    $query = "SELECT two_factor_secret, two_factor_enabled FROM users WHERE user_id = :user_id";
    $stmt = $db->prepare($query);
    $stmt->execute(['user_id' => $user_id]);
    $user = $stmt->fetch();
    
    if (!$user || !$user['two_factor_secret']) {
        die("Error: No 2FA secret found for this user. Please contact administrator.");
    }
    
    $secret = $user['two_factor_secret'];
    $qrCodeUrl = generate2FAQRCode($secret, $email, TWO_FACTOR_ISSUER);
    
} catch (PDOException $e) {
    error_log("QR Code Error: " . $e->getMessage());
    die("An error occurred. Please try again.");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📱 Scan QR Code - Lovejoy's Antiques</title>
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
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
            text-align: center;
        }
        
        h1 {
            color: #333;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }
        
        .qr-box {
            background: #f8f9fa;
            border: 3px solid #667eea;
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
        }
        
        .qr-box img {
            max-width: 250px;
            width: 100%;
            height: auto;
            display: block;
            margin: 0 auto;
        }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            border-radius: 5px;
        }
        
        .info-box p {
            margin: 8px 0;
            color: #555;
            font-size: 14px;
        }
        
        .secret-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
        }
        
        .secret-box h3 {
            color: #856404;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .secret-key {
            font-family: 'Courier New', monospace;
            font-size: 20px;
            letter-spacing: 3px;
            color: #333;
            background: white;
            padding: 15px;
            border-radius: 5px;
            font-weight: bold;
            word-break: break-all;
        }
        
        .instructions {
            text-align: left;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .instructions h3 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .instructions ol {
            margin-left: 20px;
        }
        
        .instructions li {
            color: #666;
            margin-bottom: 10px;
            line-height: 1.6;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 10px 5px;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
            margin: 10px 0;
        }
        
        .badge-enabled {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .badge-disabled {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffc107;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📱 Scan QR Code</h1>
        <p class="subtitle">Please scan this QR code with your authenticator app<br>(Google Authenticator, Authy, or similar)</p>
        
        <div class="info-box">
            <p><strong>Account:</strong> <?php echo htmlspecialchars($full_name); ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($email); ?></p>
            <p><strong>2FA Status:</strong> 
                <span class="status-badge <?php echo $user['two_factor_enabled'] ? 'badge-enabled' : 'badge-disabled'; ?>">
                    <?php echo $user['two_factor_enabled'] ? '✅ Enabled' : '⚠️ Not Yet Verified'; ?>
                </span>
            </p>
        </div>
        
        <div class="qr-box">
            <img src="<?php echo htmlspecialchars($qrCodeUrl); ?>" alt="2FA QR Code">
        </div>
        
        <div class="secret-box">
            <h3>🔑 Can't Scan? Enter Manually:</h3>
            <div class="secret-key"><?php echo htmlspecialchars($secret); ?></div>
        </div>
        
        <div class="instructions">
            <h3>📝 How to Set Up:</h3>
            <ol>
                <li><strong>Download an authenticator app</strong> if you haven't already:
                    <ul style="margin-top: 5px;">
                        <li>Google Authenticator (iOS/Android)</li>
                        <li>Microsoft Authenticator (iOS/Android)</li>
                        <li>Authy (iOS/Android/Desktop)</li>
                    </ul>
                </li>
                <li><strong>Open the app</strong> and tap "Add Account" or the "+" button</li>
                <li><strong>Scan this QR code</strong> with your phone's camera</li>
                <li><strong>Or enter the secret key manually</strong> if scanning doesn't work</li>
                <li><strong>The app will show a 6-digit code</strong> that changes every 30 seconds</li>
                <li><strong>Use this code when logging in</strong> after entering your password</li>
            </ol>
        </div>
        
        <div style="margin-top: 30px;">
            <a href="verify_2fa.php" class="btn">Test Your 2FA Code</a>
            <a href="dashboard.php" class="btn btn-secondary">Done - Return to Login</a>
        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; text-align: left;">
            <p style="color: #856404; font-size: 14px; margin: 0;">
                <strong>⚠️ Important:</strong> After scanning, return to the login page and enter the 6-digit code 
                from your app. You'll need this code every time you log in.
            </p>
        </div>
    </div>
</body>
</html>
