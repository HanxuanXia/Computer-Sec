<?php
/**
 * DASHBOARD - Main page after login
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Require authentication (also prevents page caching)
requireLogin();

// Check if user has 2FA enabled
$user_2fa_enabled = false;
if (TWO_FACTOR_ENABLED) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        $stmt = $db->prepare("SELECT two_factor_enabled FROM users WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user_data = $stmt->fetch();
        $user_2fa_enabled = $user_data && $user_data['two_factor_enabled'];
    } catch (Exception $e) {
        error_log("Error checking 2FA status: " . $e->getMessage());
    }
}

$user_name = $_SESSION['full_name'] ?? 'User';
$user_role = $_SESSION['role'] ?? 'customer';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Lovejoy's Antique Evaluation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .navbar-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .navbar h1 {
            font-size: 24px;
        }
        
        .navbar-links {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .navbar-links a {
            color: white;
            text-decoration: none;
            font-weight: 500;
            transition: opacity 0.3s;
        }
        
        .navbar-links a:hover {
            opacity: 0.8;
        }
        
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .welcome-box {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .welcome-box h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .welcome-box p {
            color: #666;
        }
        
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 20px;
        }
        
        .card p {
            color: #666;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-logout {
            background: #e74c3c;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-danger {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>🏺 Lovejoy's Antiques</h1>
            <div class="navbar-links">
                <span>Welcome, <?php echo htmlspecialchars($user_name); ?>!</span>
                <a href="dashboard.php">Dashboard</a>
                <?php if ($user_role === 'admin'): ?>
                    <a href="admin_requests.php">Requests</a>
                    <a href="admin_users.php">Users</a>
                <?php else: ?>
                    <a href="request_evaluation.php">Request Evaluation</a>
                    <a href="my_requests.php">My Requests</a>
                <?php endif; ?>
                <a href="logout.php" class="btn btn-logout" style="padding: 8px 16px; font-size: 14px;">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <?php if (isset($_GET['error']) && $_GET['error'] === 'unauthorized'): ?>
            <div class="alert alert-danger">
                You don't have permission to access that page.
            </div>
        <?php endif; ?>
        
        <div class="welcome-box">
            <h2>Welcome to Lovejoy's Antique Evaluation System</h2>
            <p>Your trusted partner in antique appraisal and authentication.</p>
        </div>
        
        <div class="cards">
            <?php if ($user_role === 'customer'): ?>
                <div class="card">
                    <h3>📝 Request Evaluation</h3>
                    <p>Submit a new evaluation request for your antique items. Upload photos and provide detailed descriptions.</p>
                    <a href="request_evaluation.php" class="btn">New Request</a>
                </div>
                
                <div class="card">
                    <h3>📋 My Requests</h3>
                    <p>View the status of your evaluation requests and track their progress through our system.</p>
                    <a href="my_requests.php" class="btn">View Requests</a>
                </div>
                
                <?php if (TWO_FACTOR_ENABLED): ?>
                <div class="card" style="border: 2px solid <?php echo $user_2fa_enabled ? '#4caf50' : '#ff9800'; ?>;">
                    <h3>🔐 Two-Factor Authentication</h3>
                    <?php if ($user_2fa_enabled): ?>
                        <p style="color: #4caf50; font-weight: bold;">✅ Enabled</p>
                        <p>Your account is protected with 2FA. You'll need to enter a code from your authenticator app when logging in.</p>
                    <?php else: ?>
                        <p style="color: #ff9800; font-weight: bold;">⚠️ Not Enabled</p>
                        <p>Add an extra layer of security to your account. Requires Google Authenticator app.</p>
                        <a href="setup_2fa.php" class="btn" style="background: #ff9800;">Enable 2FA Now</a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
                
                <div class="card">
                    <h3>👤 My Profile</h3>
                    <p>Update your contact information and manage your account settings securely.</p>
                    <a href="profile.php" class="btn">Manage Profile</a>
                </div>
            <?php else: ?>
                <div class="card">
                    <h3>📋 All Evaluation Requests</h3>
                    <p>View and manage all customer evaluation requests. Update status and add admin notes.</p>
                    <a href="admin_requests.php" class="btn">View All Requests</a>
                </div>
                
                <div class="card">
                    <h3>👥 User Management</h3>
                    <p>Manage user accounts, delete users, lock/unlock accounts, verify emails, and reset 2FA.</p>
                    <a href="admin_users.php" class="btn">Manage Users</a>
                </div>
                
                <div class="card">
                    <h3>📊 System Reports</h3>
                    <p>Generate reports on evaluation requests, user activity, and system statistics.</p>
                    <a href="system_reports.php" class="btn">View Reports</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
