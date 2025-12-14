<?php
/**
 * USER PROFILE - Manage account settings
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/security_config.php';

// Require authentication
requireLogin();

$errors = [];
$success = '';
$user_id = $_SESSION['user_id'];

// Get user data
try {
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "SELECT email, full_name, phone_number, role, two_factor_enabled, email_verified 
              FROM users WHERE user_id = :user_id";
    $stmt = $db->prepare($query);
    $stmt->execute(['user_id' => $user_id]);
    $user = $stmt->fetch();
    
    if (!$user) {
        die("User not found");
    }
} catch (PDOException $e) {
    error_log("Profile Error: " . $e->getMessage());
    die("An error occurred loading your profile");
}

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
    } else {
        $full_name = sanitizeInput($_POST['full_name'] ?? '');
        $phone_number = sanitizeInput($_POST['phone_number'] ?? '');
        
        if (empty($full_name)) {
            $errors[] = "Full name is required";
        } else {
            try {
                $updateQuery = "UPDATE users 
                               SET full_name = :full_name, 
                                   phone_number = :phone_number 
                               WHERE user_id = :user_id";
                $updateStmt = $db->prepare($updateQuery);
                $result = $updateStmt->execute([
                    'full_name' => $full_name,
                    'phone_number' => $phone_number,
                    'user_id' => $user_id
                ]);
                
                if ($result) {
                    $_SESSION['full_name'] = $full_name;
                    $user['full_name'] = $full_name;
                    $user['phone_number'] = $phone_number;
                    $success = "Profile updated successfully!";
                    logSecurityEvent('PROFILE_UPDATED', "User updated profile: " . $_SESSION['email']);
                } else {
                    $errors[] = "Failed to update profile";
                }
            } catch (PDOException $e) {
                error_log("Profile Update Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Handle password change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
    } else {
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
            $errors[] = "All password fields are required";
        } else if ($new_password !== $confirm_password) {
            $errors[] = "New passwords do not match";
        } else if (strlen($new_password) < 8) {
            $errors[] = "New password must be at least 8 characters";
        } else {
            try {
                // Verify current password
                $query = "SELECT password_hash FROM users WHERE user_id = :user_id";
                $stmt = $db->prepare($query);
                $stmt->execute(['user_id' => $user_id]);
                $userData = $stmt->fetch();
                
                if (!verifyPassword($current_password, $userData['password_hash'])) {
                    $errors[] = "Current password is incorrect";
                } else {
                    // Update password
                    $new_hash = hashPassword($new_password);
                    $updateQuery = "UPDATE users SET password_hash = :password_hash WHERE user_id = :user_id";
                    $updateStmt = $db->prepare($updateQuery);
                    $result = $updateStmt->execute([
                        'password_hash' => $new_hash,
                        'user_id' => $user_id
                    ]);
                    
                    if ($result) {
                        $success = "Password changed successfully!";
                        logSecurityEvent('PASSWORD_CHANGED', "User changed password: " . $_SESSION['email']);
                    } else {
                        $errors[] = "Failed to change password";
                    }
                }
            } catch (PDOException $e) {
                error_log("Password Change Error: " . $e->getMessage());
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
    <title>My Profile - Lovejoy's Antique Evaluation</title>
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
            max-width: 800px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .card h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="tel"],
        input[type="password"],
        input[type="email"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        input:disabled {
            background-color: #f5f5f5;
            cursor: not-allowed;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            display: inline-block;
            font-weight: 500;
            transition: background 0.3s;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background-color: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }
        
        .alert-success {
            background-color: #efe;
            border: 1px solid #cfc;
            color: #3c3;
        }
        
        .info-box {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .info-box p {
            margin: 5px 0;
            color: #555;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 14px;
            font-weight: 600;
        }
        
        .badge-success {
            background-color: #4caf50;
            color: white;
        }
        
        .badge-warning {
            background-color: #ff9800;
            color: white;
        }
        
        .divider {
            height: 1px;
            background: #e0e0e0;
            margin: 30px 0;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>🏺 Lovejoy's Antiques</h1>
            <div class="navbar-links">
                <span>Welcome, <?php echo htmlspecialchars($user['full_name']); ?>!</span>
                <a href="dashboard.php">Dashboard</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <?php foreach ($errors as $error): ?>
                    <p>⚠️ <?php echo htmlspecialchars($error); ?></p>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <p>✅ <?php echo htmlspecialchars($success); ?></p>
            </div>
        <?php endif; ?>

        <!-- Account Information -->
        <div class="card">
            <h2>📋 Account Information</h2>
            <div class="info-box">
                <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                <p><strong>Role:</strong> <?php echo htmlspecialchars(ucfirst($user['role'])); ?></p>
                <p><strong>Email Status:</strong> 
                    <span class="badge <?php echo $user['email_verified'] ? 'badge-success' : 'badge-warning'; ?>">
                        <?php echo $user['email_verified'] ? '✅ Verified' : '⚠️ Not Verified'; ?>
                    </span>
                </p>
                <p><strong>2FA Status:</strong> 
                    <span class="badge <?php echo $user['two_factor_enabled'] ? 'badge-success' : 'badge-warning'; ?>">
                        <?php echo $user['two_factor_enabled'] ? '✅ Enabled' : '⚠️ Disabled'; ?>
                    </span>
                </p>
            </div>
            
            <?php if (TWO_FACTOR_ENABLED && !$user['two_factor_enabled']): ?>
                <p style="margin-top: 15px;">
                    <a href="setup_2fa.php" class="btn">🔐 Enable Two-Factor Authentication</a>
                </p>
            <?php endif; ?>
        </div>

        <!-- Update Profile -->
        <div class="card">
            <h2>✏️ Update Profile</h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" 
                           value="<?php echo htmlspecialchars($user['email']); ?>" 
                           disabled>
                    <small style="color: #777;">Email cannot be changed. Contact support if needed.</small>
                </div>
                
                <div class="form-group">
                    <label for="full_name">Full Name *</label>
                    <input type="text" id="full_name" name="full_name" 
                           value="<?php echo htmlspecialchars($user['full_name']); ?>" 
                           required>
                </div>
                
                <div class="form-group">
                    <label for="phone_number">Phone Number</label>
                    <input type="tel" id="phone_number" name="phone_number" 
                           value="<?php echo htmlspecialchars($user['phone_number'] ?? ''); ?>" 
                           placeholder="+1 (555) 123-4567">
                </div>
                
                <button type="submit" name="update_profile" class="btn">💾 Save Changes</button>
            </form>
        </div>

        <!-- Change Password -->
        <div class="card">
            <h2>🔒 Change Password</h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="current_password">Current Password *</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                
                <div class="form-group">
                    <label for="new_password">New Password *</label>
                    <input type="password" id="new_password" name="new_password" 
                           minlength="8" required>
                    <small style="color: #777;">Must be at least 8 characters</small>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password *</label>
                    <input type="password" id="confirm_password" name="confirm_password" 
                           minlength="8" required>
                </div>
                
                <button type="submit" name="change_password" class="btn">🔐 Change Password</button>
            </form>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <a href="dashboard.php" class="btn-secondary">← Back to Dashboard</a>
        </div>
    </div>

    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
