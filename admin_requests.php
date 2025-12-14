<?php
/**
 * TASK 5: ADMIN EVALUATION REQUESTS PAGE (5 marks - Code Quality)
 * 
 * Security Features Implemented:
 * 1. Admin Authorization Required - Only admins can access this page
 * 2. Role-Based Access Control (RBAC) - Checks user role before granting access
 * 3. CSRF Protection - Validates CSRF token on status updates
 * 4. SQL Injection Prevention - Uses PDO prepared statements
 * 5. XSS Prevention - Sanitizes all output
 * 6. Audit Logging - Tracks all admin actions
 * 7. Input Validation - Validates status values against whitelist
 * 8. Session Security - Validates admin session on every request
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// SECURITY EVIDENCE 1 & 2: Admin Authorization Required (RBAC)
requireAdmin();

$errors = [];
$success = '';

// Handle status update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_status') {
    // SECURITY EVIDENCE 3: CSRF Protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('ADMIN_UPDATE_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $request_id = intval($_POST['request_id'] ?? 0);
        $new_status = sanitizeInput($_POST['new_status'] ?? '');
        $admin_notes = sanitizeInput($_POST['admin_notes'] ?? '');
        
        // SECURITY EVIDENCE 7: Input Validation (Whitelist)
        $allowed_statuses = ['pending', 'in_progress', 'completed', 'cancelled'];
        
        if (!in_array($new_status, $allowed_statuses)) {
            $errors[] = "Invalid status value";
        } else if ($request_id <= 0) {
            $errors[] = "Invalid request ID";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // SECURITY EVIDENCE 4: SQL Injection Prevention (Prepared Statement)
                $updateQuery = "UPDATE evaluation_requests 
                               SET status = :status, 
                                   admin_notes = :admin_notes,
                                   updated_at = NOW()
                               WHERE request_id = :request_id";
                
                $stmt = $db->prepare($updateQuery);
                $result = $stmt->execute([
                    'status' => $new_status,
                    'admin_notes' => $admin_notes,
                    'request_id' => $request_id
                ]);
                
                if ($result) {
                    $success = "Request #$request_id updated successfully";
                    
                    // SECURITY EVIDENCE 6: Audit Logging
                    logSecurityEvent('ADMIN_REQUEST_UPDATED', 
                        "Admin updated request #$request_id to status: $new_status");
                } else {
                    $errors[] = "Failed to update request";
                }
                
            } catch (PDOException $e) {
                error_log("Admin Update Error: " . $e->getMessage());
                $errors[] = "An error occurred while updating the request";
            }
        }
    }
}

// Fetch all evaluation requests with user information
try {
    $database = new Database();
    $db = $database->getConnection();
    
    // SECURITY EVIDENCE 4: SQL Injection Prevention
    $query = "SELECT 
                er.request_id,
                er.object_description,
                er.contact_method,
                er.photo_filename,
                er.status,
                er.admin_notes,
                er.created_at,
                er.updated_at,
                u.full_name,
                u.email,
                u.phone_number
              FROM evaluation_requests er
              JOIN users u ON er.user_id = u.user_id
              ORDER BY 
                CASE er.status
                    WHEN 'pending' THEN 1
                    WHEN 'in_progress' THEN 2
                    WHEN 'completed' THEN 3
                    WHEN 'cancelled' THEN 4
                END,
                er.created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute();
    $requests = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Fetch Requests Error: " . $e->getMessage());
    $requests = [];
    $errors[] = "Failed to load requests";
}

$csrf_token = generateCSRFToken();
$admin_name = $_SESSION['full_name'] ?? 'Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - All Evaluation Requests</title>
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
        
        .admin-badge {
            background: #ffc107;
            color: #333;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .container {
            max-width: 1400px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .page-header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .page-header h2 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .page-header p {
            color: #666;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 32px;
            margin-bottom: 5px;
        }
        
        .stat-card p {
            color: #666;
            font-size: 14px;
        }
        
        .stat-card.pending h3 { color: #f39c12; }
        .stat-card.in-progress h3 { color: #3498db; }
        .stat-card.completed h3 { color: #27ae60; }
        .stat-card.cancelled h3 { color: #e74c3c; }
        
        .requests-container {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
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
        
        .request-item {
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: border-color 0.3s;
        }
        
        .request-item:hover {
            border-color: #667eea;
        }
        
        .request-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .request-id {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }
        
        .status-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .status-in_progress {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .status-completed {
            background: #d4edda;
            color: #155724;
        }
        
        .status-cancelled {
            background: #f8d7da;
            color: #721c24;
        }
        
        .request-details {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .detail-section h4 {
            color: #333;
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .detail-section p {
            color: #666;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .customer-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
        }
        
        .customer-info p {
            margin-bottom: 8px;
        }
        
        .customer-info strong {
            color: #333;
        }
        
        .admin-section {
            border-top: 2px solid #e0e0e0;
            padding-top: 15px;
            margin-top: 15px;
        }
        
        .admin-form {
            display: grid;
            grid-template-columns: 200px 1fr auto;
            gap: 15px;
            align-items: start;
        }
        
        .admin-form select,
        .admin-form textarea {
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            font-family: inherit;
        }
        
        .admin-form textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .photo-thumbnail {
            max-width: 200px;
            max-height: 200px;
            border-radius: 8px;
            margin-top: 10px;
            cursor: pointer;
            border: 2px solid #e0e0e0;
            transition: transform 0.2s;
        }
        
        .photo-thumbnail:hover {
            transform: scale(1.05);
            border-color: #667eea;
        }
        
        .photo-placeholder {
            display: inline-block;
            padding: 20px 30px;
            background: #f8f9fa;
            border: 2px dashed #ddd;
            border-radius: 8px;
            margin-top: 10px;
            text-align: center;
        }
        
        .photo-placeholder span {
            display: block;
            font-size: 48px;
            margin-bottom: 10px;
            opacity: 0.5;
        }
        
        .photo-placeholder p {
            margin: 5px 0;
            color: #666;
            font-size: 14px;
        }
        
        .photo-placeholder small {
            color: #999;
            font-size: 12px;
        }
        
        .no-requests {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        
        .no-requests h3 {
            font-size: 24px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <h1>🏺 Lovejoy's Antiques - Admin Panel</h1>
            <div class="navbar-links">
                <span class="admin-badge">ADMIN</span>
                <span><?php echo htmlspecialchars($admin_name); ?></span>
                <a href="dashboard.php">Dashboard</a>
                <a href="admin_requests.php">Requests</a>
                <a href="admin_users.php">Users</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="page-header">
            <h2>📋 All Evaluation Requests</h2>
            <p>Manage and respond to customer evaluation requests</p>
        </div>
        
        <?php
        // Calculate statistics
        $stats = [
            'pending' => 0,
            'in_progress' => 0,
            'completed' => 0,
            'cancelled' => 0
        ];
        
        foreach ($requests as $req) {
            if (isset($stats[$req['status']])) {
                $stats[$req['status']]++;
            }
        }
        ?>
        
        <div class="stats">
            <div class="stat-card pending">
                <h3><?php echo $stats['pending']; ?></h3>
                <p>Pending</p>
            </div>
            <div class="stat-card in-progress">
                <h3><?php echo $stats['in_progress']; ?></h3>
                <p>In Progress</p>
            </div>
            <div class="stat-card completed">
                <h3><?php echo $stats['completed']; ?></h3>
                <p>Completed</p>
            </div>
            <div class="stat-card cancelled">
                <h3><?php echo $stats['cancelled']; ?></h3>
                <p>Cancelled</p>
            </div>
        </div>
        
        <div class="requests-container">
            <?php if (!empty($success)): ?>
                <div class="alert alert-success">
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <div><?php echo htmlspecialchars($error); ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if (empty($requests)): ?>
                <div class="no-requests">
                    <h3>No evaluation requests found</h3>
                    <p>All evaluation requests will appear here</p>
                </div>
            <?php else: ?>
                <?php foreach ($requests as $request): ?>
                    <div class="request-item">
                        <div class="request-header">
                            <div class="request-id">
                                Request #<?php echo htmlspecialchars($request['request_id']); ?>
                            </div>
                            <div class="status-badge status-<?php echo htmlspecialchars($request['status']); ?>">
                                <?php echo htmlspecialchars(str_replace('_', ' ', $request['status'])); ?>
                            </div>
                        </div>
                        
                        <div class="request-details">
                            <div class="detail-section">
                                <h4>Object Description:</h4>
                                <p><?php echo nl2br(htmlspecialchars($request['object_description'])); ?></p>
                                
                                <?php if (!empty($request['photo_filename'])): ?>
                                    <?php 
                                    $photoPath = __DIR__ . '/uploads/' . $request['photo_filename'];
                                    if (file_exists($photoPath)): 
                                    ?>
                                        <img src="uploads/<?php echo htmlspecialchars($request['photo_filename']); ?>" 
                                             alt="Object photo" 
                                             class="photo-thumbnail"
                                             onclick="window.open(this.src, '_blank')"
                                             title="Click to view full size">
                                    <?php else: ?>
                                        <div class="photo-placeholder">
                                            <span>📷</span>
                                            <p>Photo: <?php echo htmlspecialchars($request['photo_filename']); ?></p>
                                            <small>(File not found on server)</small>
                                        </div>
                                    <?php endif; ?>
                                <?php else: ?>
                                    <div class="photo-placeholder">
                                        <span>📷</span>
                                        <p>No photo uploaded</p>
                                    </div>
                                <?php endif; ?>
                            </div>
                            
                            <div class="customer-info">
                                <h4 style="margin-bottom: 10px;">Customer Information:</h4>
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($request['full_name']); ?></p>
                                <p><strong>Email:</strong> <?php echo htmlspecialchars($request['email']); ?></p>
                                <p><strong>Phone:</strong> <?php echo htmlspecialchars($request['phone_number']); ?></p>
                                <p><strong>Preferred Contact:</strong> 
                                    <?php echo htmlspecialchars(ucfirst($request['contact_method'])); ?>
                                </p>
                                <p><strong>Submitted:</strong> 
                                    <?php echo date('M d, Y H:i', strtotime($request['created_at'])); ?>
                                </p>
                            </div>
                        </div>
                        
                        <div class="admin-section">
                            <h4>Admin Actions:</h4>
                            <form method="POST" action="" class="admin-form">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                <input type="hidden" name="action" value="update_status">
                                <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request['request_id']); ?>">
                                
                                <select name="new_status" required>
                                    <option value="pending" <?php echo $request['status'] === 'pending' ? 'selected' : ''; ?>>
                                        Pending
                                    </option>
                                    <option value="in_progress" <?php echo $request['status'] === 'in_progress' ? 'selected' : ''; ?>>
                                        In Progress
                                    </option>
                                    <option value="completed" <?php echo $request['status'] === 'completed' ? 'selected' : ''; ?>>
                                        Completed
                                    </option>
                                    <option value="cancelled" <?php echo $request['status'] === 'cancelled' ? 'selected' : ''; ?>>
                                        Cancelled
                                    </option>
                                </select>
                                
                                <textarea name="admin_notes" 
                                         placeholder="Add admin notes..."><?php echo htmlspecialchars($request['admin_notes'] ?? ''); ?></textarea>
                                
                                <button type="submit" class="btn">Update</button>
                            </form>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
    
    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
