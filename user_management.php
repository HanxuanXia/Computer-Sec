<?php
/**
 * USER MANAGEMENT - Admin page to manage users
 * Security: Admin-only access
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// Require authentication and admin role
requireLogin();
requireAdmin();

$success = '';
$errors = [];

// Handle user role update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_role') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('USER_MANAGEMENT_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $user_id = intval($_POST['user_id'] ?? 0);
        $new_role = $_POST['new_role'] ?? '';
        
        if ($user_id <= 0) {
            $errors[] = "Invalid user ID";
        } else if (!in_array($new_role, ['customer', 'admin'])) {
            $errors[] = "Invalid role specified";
        } else if ($user_id == $_SESSION['user_id']) {
            $errors[] = "You cannot change your own role";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                $updateQuery = "UPDATE users SET role = :role WHERE user_id = :user_id";
                $stmt = $db->prepare($updateQuery);
                $result = $stmt->execute([
                    'role' => $new_role,
                    'user_id' => $user_id
                ]);
                
                if ($result) {
                    $success = "User role updated successfully";
                    logSecurityEvent('USER_ROLE_UPDATED', 
                        "Admin {$_SESSION['email']} updated user ID $user_id to role: $new_role");
                } else {
                    $errors[] = "Failed to update user role";
                }
            } catch (PDOException $e) {
                error_log("Update Role Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Handle user status toggle (enable/disable)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('USER_MANAGEMENT_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $user_id = intval($_POST['user_id'] ?? 0);
        $new_status = $_POST['new_status'] ?? 'active';
        
        if ($user_id <= 0) {
            $errors[] = "Invalid user ID";
        } else if ($user_id == $_SESSION['user_id']) {
            $errors[] = "You cannot disable your own account";
        } else if (!in_array($new_status, ['active', 'locked'])) {
            $errors[] = "Invalid status specified";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                $updateQuery = "UPDATE users SET account_status = :account_status WHERE user_id = :user_id";
                $stmt = $db->prepare($updateQuery);
                $result = $stmt->execute([
                    'account_status' => $new_status,
                    'user_id' => $user_id
                ]);
                
                if ($result) {
                    $status_text = ($new_status === 'active') ? 'enabled' : 'disabled';
                    $success = "User account $status_text successfully";
                    logSecurityEvent('USER_STATUS_UPDATED', 
                        "Admin {$_SESSION['email']} $status_text user ID $user_id");
                } else {
                    $errors[] = "Failed to update user status";
                }
            } catch (PDOException $e) {
                error_log("Update Status Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Fetch all users
try {
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "SELECT 
                user_id,
                full_name,
                email,
                role,
                account_status,
                created_at,
                last_login
              FROM users
              ORDER BY created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute();
    $users = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Fetch Users Error: " . $e->getMessage());
    $errors[] = "Failed to load users";
    $users = [];
}

// Get statistics
try {
    $statsQuery = "SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                    SUM(CASE WHEN role = 'customer' THEN 1 ELSE 0 END) as customer_count,
                    SUM(CASE WHEN account_status = 'active' THEN 1 ELSE 0 END) as active_users,
                    SUM(CASE WHEN account_status != 'active' THEN 1 ELSE 0 END) as inactive_users
                   FROM users";
    $statsStmt = $db->prepare($statsQuery);
    $statsStmt->execute();
    $stats = $statsStmt->fetch();
} catch (PDOException $e) {
    error_log("Fetch Stats Error: " . $e->getMessage());
    $stats = null;
}

$user_name = $_SESSION['full_name'] ?? 'Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - Lovejoy's Antiques</title>
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
            max-width: 1400px;
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
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .page-header h2 {
            color: #333;
            font-size: 28px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 32px;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            color: #666;
            font-size: 14px;
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 15px;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        
        .users-table {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            color: #666;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-admin {
            background: #667eea;
            color: white;
        }
        
        .badge-customer {
            background: #28a745;
            color: white;
        }
        
        .badge-active {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-locked {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .btn {
            padding: 6px 12px;
            border-radius: 5px;
            border: none;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s;
            margin: 2px;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #333;
        }
        
        .btn-warning:hover {
            background: #e0a800;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .no-users {
            text-align: center;
            padding: 60px 20px;
            color: #999;
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
                <a href="admin_requests.php">All Requests</a>
                <a href="user_management.php">User Management</a>
                <a href="system_reports.php">Reports</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="page-header">
            <div>
                <h2>👥 User Management</h2>
                <p style="color: #666; margin-top: 5px;">Manage user accounts and permissions</p>
            </div>
        </div>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                ✅ <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                ❌ <strong>Error:</strong>
                <?php if (count($errors) === 1): ?>
                    <?php echo htmlspecialchars($errors[0]); ?>
                <?php else: ?>
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <?php if ($stats): ?>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3><?php echo $stats['total_users']; ?></h3>
                    <p>Total Users</p>
                </div>
                <div class="stat-card">
                    <h3><?php echo $stats['admin_count']; ?></h3>
                    <p>Administrators</p>
                </div>
                <div class="stat-card">
                    <h3><?php echo $stats['customer_count']; ?></h3>
                    <p>Customers</p>
                </div>
                <div class="stat-card">
                    <h3><?php echo $stats['active_users']; ?></h3>
                    <p>Active Users</p>
                </div>
                <div class="stat-card">
                    <h3><?php echo $stats['inactive_users']; ?></h3>
                    <p>Inactive Users</p>
                </div>
            </div>
        <?php endif; ?>
        
        <div class="users-table">
            <?php if (empty($users)): ?>
                <div class="no-users">
                    <h3>No Users Found</h3>
                    <p>There are no users in the system.</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Registered</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['user_id']); ?></td>
                                <td><strong><?php echo htmlspecialchars($user['full_name']); ?></strong></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td>
                                    <span class="badge badge-<?php echo $user['role']; ?>">
                                        <?php echo htmlspecialchars($user['role']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge badge-<?php echo $user['account_status']; ?>">
                                        <?php echo htmlspecialchars($user['account_status']); ?>
                                    </span>
                                </td>
                                <td><?php echo date('M d, Y', strtotime($user['created_at'])); ?></td>
                                <td>
                                    <?php 
                                    if ($user['last_login']) {
                                        echo date('M d, Y H:i', strtotime($user['last_login']));
                                    } else {
                                        echo '<span style="color: #999;">Never</span>';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php if ($user['user_id'] != $_SESSION['user_id']): ?>
                                        <!-- Change Role -->
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Change this user\'s role?');">
                                            <input type="hidden" name="action" value="update_role">
                                            <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                            <input type="hidden" name="new_role" value="<?php echo $user['role'] === 'admin' ? 'customer' : 'admin'; ?>">
                                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                            <button type="submit" class="btn btn-primary" title="Change Role">
                                                <?php echo $user['role'] === 'admin' ? '👤 Make Customer' : '👑 Make Admin'; ?>
                                            </button>
                                        </form>
                                        
                                        <!-- Toggle Status -->
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('<?php echo $user['account_status'] === 'active' ? 'Lock' : 'Activate'; ?> this user account?');">
                                            <input type="hidden" name="action" value="toggle_status">
                                            <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                            <input type="hidden" name="new_status" value="<?php echo $user['account_status'] === 'active' ? 'locked' : 'active'; ?>">
                                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                            <button type="submit" class="btn <?php echo $user['account_status'] === 'active' ? 'btn-warning' : 'btn-success'; ?>" title="Toggle Status">
                                                <?php echo $user['account_status'] === 'active' ? '� Lock' : '✅ Activate'; ?>
                                            </button>
                                        </form>
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
    
    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
