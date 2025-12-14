<?php
/**
 * Admin User Management Page
 * Allows administrators to view, manage, and delete user accounts
 * 
 * Security Features:
 * 1. Admin Authorization Required
 * 2. Role-Based Access Control (RBAC)
 * 3. CSRF Protection on all actions
 * 4. SQL Injection Prevention
 * 5. Audit Logging for all user management actions
 * 6. Confirmation required before deletion
 * 7. Cannot delete own account
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// Require admin access
requireAdmin();

$errors = [];
$success = '';

// Get current admin user ID
$current_admin_id = $_SESSION['user_id'];

// Handle user actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('ADMIN_USER_MGMT_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $action = $_POST['action'] ?? '';
        $user_id = intval($_POST['user_id'] ?? 0);
        
        if ($user_id <= 0) {
            $errors[] = "Invalid user ID";
        } else if ($user_id == $current_admin_id) {
            $errors[] = "You cannot perform this action on your own account";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // Get user details for logging
                $userQuery = "SELECT email, full_name, role FROM users WHERE user_id = :user_id";
                $userStmt = $db->prepare($userQuery);
                $userStmt->execute(['user_id' => $user_id]);
                $user = $userStmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$user) {
                    $errors[] = "User not found";
                } else {
                    switch ($action) {
                        case 'delete_user':
                            // Delete user account
                            $deleteQuery = "DELETE FROM users WHERE user_id = :user_id";
                            $deleteStmt = $db->prepare($deleteQuery);
                            $result = $deleteStmt->execute(['user_id' => $user_id]);
                            
                            if ($result) {
                                $success = "User '{$user['email']}' has been successfully deleted";
                                logSecurityEvent('ADMIN_USER_DELETED', 
                                    "Admin deleted user: {$user['email']} (ID: $user_id, Name: {$user['full_name']})");
                            } else {
                                $errors[] = "Failed to delete user";
                            }
                            break;
                            
                        case 'lock_account':
                            // Lock user account
                            $lockQuery = "UPDATE users SET account_status = 'locked' WHERE user_id = :user_id";
                            $lockStmt = $db->prepare($lockQuery);
                            $result = $lockStmt->execute(['user_id' => $user_id]);
                            
                            if ($result) {
                                $success = "Account '{$user['email']}' has been locked";
                                logSecurityEvent('ADMIN_USER_LOCKED', 
                                    "Admin locked user: {$user['email']} (ID: $user_id)");
                            } else {
                                $errors[] = "Failed to lock account";
                            }
                            break;
                            
                        case 'unlock_account':
                            // Unlock user account
                            $unlockQuery = "UPDATE users SET account_status = 'active', failed_login_attempts = 0 WHERE user_id = :user_id";
                            $unlockStmt = $db->prepare($unlockQuery);
                            $result = $unlockStmt->execute(['user_id' => $user_id]);
                            
                            if ($result) {
                                $success = "Account '{$user['email']}' has been unlocked";
                                logSecurityEvent('ADMIN_USER_UNLOCKED', 
                                    "Admin unlocked user: {$user['email']} (ID: $user_id)");
                            } else {
                                $errors[] = "Failed to unlock account";
                            }
                            break;
                            
                        case 'verify_email':
                            // Manually verify user email
                            $verifyQuery = "UPDATE users SET email_verified = 1, account_status = 'active' WHERE user_id = :user_id";
                            $verifyStmt = $db->prepare($verifyQuery);
                            $result = $verifyStmt->execute(['user_id' => $user_id]);
                            
                            if ($result) {
                                $success = "Email verified for '{$user['email']}'";
                                logSecurityEvent('ADMIN_EMAIL_VERIFIED', 
                                    "Admin verified email for: {$user['email']} (ID: $user_id)");
                            } else {
                                $errors[] = "Failed to verify email";
                            }
                            break;
                            
                        case 'reset_2fa':
                            // Reset 2FA for user
                            $resetQuery = "UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE user_id = :user_id";
                            $resetStmt = $db->prepare($resetQuery);
                            $result = $resetStmt->execute(['user_id' => $user_id]);
                            
                            if ($result) {
                                $success = "2FA reset for '{$user['email']}' - User will need to set up 2FA again";
                                logSecurityEvent('ADMIN_2FA_RESET', 
                                    "Admin reset 2FA for: {$user['email']} (ID: $user_id)");
                            } else {
                                $errors[] = "Failed to reset 2FA";
                            }
                            break;
                            
                        default:
                            $errors[] = "Invalid action";
                    }
                }
                
            } catch (PDOException $e) {
                error_log("Admin User Management Error: " . $e->getMessage());
                $errors[] = "An error occurred while performing the action";
            }
        }
    }
}

// Fetch all users
try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Get filter
    $filter = $_GET['filter'] ?? 'all';
    $search = $_GET['search'] ?? '';
    
    $query = "SELECT 
                user_id,
                email,
                full_name,
                phone_number,
                role,
                account_status,
                two_factor_enabled,
                email_verified,
                failed_login_attempts,
                last_login,
                created_at
              FROM users 
              WHERE 1=1";
    
    $params = [];
    
    // Apply filters
    if ($filter === 'customers') {
        $query .= " AND role = 'customer'";
    } else if ($filter === 'admins') {
        $query .= " AND role = 'admin'";
    } else if ($filter === 'locked') {
        $query .= " AND account_status = 'locked'";
    } else if ($filter === 'pending') {
        $query .= " AND account_status = 'pending'";
    } else if ($filter === 'unverified') {
        $query .= " AND email_verified = 0";
    }
    
    // Apply search
    if (!empty($search)) {
        $query .= " AND (email LIKE :search OR full_name LIKE :search OR phone_number LIKE :search)";
        $params['search'] = "%$search%";
    }
    
    $query .= " ORDER BY created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get statistics
    $statsQuery = "SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                    SUM(CASE WHEN role = 'customer' THEN 1 ELSE 0 END) as customer_count,
                    SUM(CASE WHEN account_status = 'locked' THEN 1 ELSE 0 END) as locked_count,
                    SUM(CASE WHEN account_status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                    SUM(CASE WHEN email_verified = 0 THEN 1 ELSE 0 END) as unverified_count,
                    SUM(CASE WHEN two_factor_enabled = 1 THEN 1 ELSE 0 END) as twofa_count
                   FROM users";
    $statsStmt = $db->query($statsQuery);
    $stats = $statsStmt->fetch(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    error_log("Fetch Users Error: " . $e->getMessage());
    $errors[] = "Failed to load users";
    $users = [];
    $stats = [];
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - Admin Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #333;
            font-size: 28px;
        }
        
        .nav-links {
            display: flex;
            gap: 15px;
        }
        
        .nav-links a {
            padding: 10px 20px;
            background: #8b7355;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .nav-links a:hover {
            background: #6d5840;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card .number {
            font-size: 36px;
            font-weight: bold;
            color: #8b7355;
            margin-bottom: 5px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 14px;
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .filters {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            color: #333;
            font-size: 14px;
        }
        
        .filter-btn.active {
            background: #8b7355;
            color: white;
            border-color: #8b7355;
        }
        
        .filter-btn:hover {
            border-color: #8b7355;
        }
        
        .search-box {
            flex: 1;
            min-width: 300px;
        }
        
        .search-box input {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .users-table {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #8b7355;
            color: white;
        }
        
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            font-weight: 600;
            font-size: 14px;
        }
        
        td {
            font-size: 13px;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .badge-admin {
            background: #667eea;
            color: white;
        }
        
        .badge-customer {
            background: #51cf66;
            color: white;
        }
        
        .badge-active {
            background: #51cf66;
            color: white;
        }
        
        .badge-locked {
            background: #dc3545;
            color: white;
        }
        
        .badge-pending {
            background: #ffc107;
            color: #333;
        }
        
        .badge-verified {
            background: #28a745;
            color: white;
        }
        
        .badge-unverified {
            background: #6c757d;
            color: white;
        }
        
        .actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #333;
        }
        
        .btn-warning:hover {
            background: #e0a800;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .btn-info {
            background: #17a2b8;
            color: white;
        }
        
        .btn-info:hover {
            background: #138496;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background: white;
            margin: 10% auto;
            padding: 30px;
            border-radius: 10px;
            max-width: 500px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .modal-header {
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            color: #dc3545;
            font-size: 24px;
        }
        
        .modal-body {
            margin-bottom: 20px;
            color: #333;
            line-height: 1.6;
        }
        
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        .btn-modal {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
        }
        
        .btn-cancel {
            background: #6c757d;
            color: white;
        }
        
        .btn-confirm {
            background: #dc3545;
            color: white;
        }
        
        .no-users {
            padding: 40px;
            text-align: center;
            color: #666;
        }
        
        @media (max-width: 1200px) {
            .users-table {
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👥 User Management</h1>
            <div class="nav-links">
                <a href="dashboard.php">Dashboard</a>
                <a href="admin_requests.php">Evaluation Requests</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <?php foreach ($errors as $error): ?>
                    <div><?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number"><?php echo $stats['total_users'] ?? 0; ?></div>
                <div class="label">Total Users</div>
            </div>
            <div class="stat-card">
                <div class="number"><?php echo $stats['customer_count'] ?? 0; ?></div>
                <div class="label">Customers</div>
            </div>
            <div class="stat-card">
                <div class="number"><?php echo $stats['admin_count'] ?? 0; ?></div>
                <div class="label">Administrators</div>
            </div>
            <div class="stat-card">
                <div class="number"><?php echo $stats['locked_count'] ?? 0; ?></div>
                <div class="label">Locked Accounts</div>
            </div>
            <div class="stat-card">
                <div class="number"><?php echo $stats['pending_count'] ?? 0; ?></div>
                <div class="label">Pending Verification</div>
            </div>
            <div class="stat-card">
                <div class="number"><?php echo $stats['twofa_count'] ?? 0; ?></div>
                <div class="label">2FA Enabled</div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters">
            <a href="?filter=all" class="filter-btn <?php echo ($filter === 'all') ? 'active' : ''; ?>">All Users</a>
            <a href="?filter=customers" class="filter-btn <?php echo ($filter === 'customers') ? 'active' : ''; ?>">Customers</a>
            <a href="?filter=admins" class="filter-btn <?php echo ($filter === 'admins') ? 'active' : ''; ?>">Admins</a>
            <a href="?filter=locked" class="filter-btn <?php echo ($filter === 'locked') ? 'active' : ''; ?>">Locked</a>
            <a href="?filter=pending" class="filter-btn <?php echo ($filter === 'pending') ? 'active' : ''; ?>">Pending</a>
            <a href="?filter=unverified" class="filter-btn <?php echo ($filter === 'unverified') ? 'active' : ''; ?>">Unverified</a>
            
            <div class="search-box">
                <form method="GET" action="">
                    <input type="hidden" name="filter" value="<?php echo htmlspecialchars($filter); ?>">
                    <input type="text" name="search" placeholder="Search by email, name, or phone..." 
                           value="<?php echo htmlspecialchars($search); ?>">
                </form>
            </div>
        </div>
        
        <!-- Users Table -->
        <div class="users-table">
            <?php if (empty($users)): ?>
                <div class="no-users">
                    <p>No users found matching your criteria.</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Phone</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Email</th>
                            <th>2FA</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['user_id']); ?></td>
                                <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td><?php echo htmlspecialchars($user['phone_number']); ?></td>
                                <td>
                                    <span class="badge badge-<?php echo $user['role']; ?>">
                                        <?php echo strtoupper($user['role']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge badge-<?php echo $user['account_status']; ?>">
                                        <?php echo strtoupper($user['account_status']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge badge-<?php echo $user['email_verified'] ? 'verified' : 'unverified'; ?>">
                                        <?php echo $user['email_verified'] ? '✓ Verified' : '✗ Unverified'; ?>
                                    </span>
                                </td>
                                <td><?php echo $user['two_factor_enabled'] ? '✓ Yes' : '✗ No'; ?></td>
                                <td><?php echo $user['last_login'] ? date('Y-m-d H:i', strtotime($user['last_login'])) : 'Never'; ?></td>
                                <td class="actions">
                                    <?php if ($user['user_id'] != $current_admin_id): ?>
                                        
                                        <?php if ($user['account_status'] === 'locked'): ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="unlock_account">
                                                <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                <button type="submit" class="btn btn-success" title="Unlock Account">
                                                    🔓 Unlock
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="lock_account">
                                                <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                <button type="submit" class="btn btn-warning" title="Lock Account">
                                                    🔒 Lock
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <?php if (!$user['email_verified']): ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="verify_email">
                                                <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                <button type="submit" class="btn btn-info" title="Verify Email">
                                                    ✓ Verify
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['two_factor_enabled']): ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="reset_2fa">
                                                <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                <button type="submit" class="btn btn-warning" title="Reset 2FA">
                                                    🔄 Reset 2FA
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <button class="btn btn-danger" 
                                                onclick="confirmDelete(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['email'], ENT_QUOTES); ?>')"
                                                title="Delete User">
                                            🗑️ Delete
                                        </button>
                                        
                                    <?php else: ?>
                                        <span style="color: #999; font-size: 12px;">Your Account</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Delete Confirmation Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>⚠️ Confirm User Deletion</h2>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete this user?</p>
                <p><strong>Email:</strong> <span id="deleteUserEmail"></span></p>
                <p style="color: #dc3545; margin-top: 15px;">
                    <strong>Warning:</strong> This action cannot be undone. All user data, evaluation requests, and associated records will be permanently deleted.
                </p>
            </div>
            <div class="modal-footer">
                <button class="btn-modal btn-cancel" onclick="closeDeleteModal()">Cancel</button>
                <form id="deleteForm" method="POST" style="display:inline;">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="user_id" id="deleteUserId">
                    <button type="submit" class="btn-modal btn-confirm">Yes, Delete User</button>
                </form>
            </div>
        </div>
    </div>
    
    <script>
        function confirmDelete(userId, userEmail) {
            document.getElementById('deleteUserId').value = userId;
            document.getElementById('deleteUserEmail').textContent = userEmail;
            document.getElementById('deleteModal').style.display = 'block';
        }
        
        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('deleteModal');
            if (event.target == modal) {
                closeDeleteModal();
            }
        }
        
        // Auto-hide success message after 5 seconds
        setTimeout(function() {
            const successAlert = document.querySelector('.alert-success');
            if (successAlert) {
                successAlert.style.transition = 'opacity 0.5s';
                successAlert.style.opacity = '0';
                setTimeout(function() {
                    successAlert.style.display = 'none';
                }, 500);
            }
        }, 5000);
    </script>
</body>
</html>
