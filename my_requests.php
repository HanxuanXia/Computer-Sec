<?php
/**
 * MY REQUESTS - View customer's own evaluation requests
 * Feature: Users can cancel their pending requests
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// Require authentication
requireLogin();

$success = '';
$errors = [];

// Handle cancel request action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'cancel_request') {
    // CSRF protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('CANCEL_REQUEST_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $request_id = intval($_POST['request_id'] ?? 0);
        
        if ($request_id <= 0) {
            $errors[] = "Invalid request ID";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // First, verify the request belongs to the current user and status is pending
                $checkQuery = "SELECT request_id, status, user_id FROM evaluation_requests 
                              WHERE request_id = :request_id";
                $checkStmt = $db->prepare($checkQuery);
                $checkStmt->execute(['request_id' => $request_id]);
                $requestData = $checkStmt->fetch();
                
                if (!$requestData) {
                    $errors[] = "Request not found";
                } else if ($requestData['user_id'] != $_SESSION['user_id']) {
                    $errors[] = "You don't have permission to cancel this request";
                    logSecurityEvent('UNAUTHORIZED_CANCEL_ATTEMPT', 
                        "User {$_SESSION['user_id']} tried to cancel request belonging to user {$requestData['user_id']}");
                } else if ($requestData['status'] !== 'pending') {
                    $errors[] = "Only pending requests can be cancelled. This request is already '{$requestData['status']}'";
                } else {
                    // Execute cancel operation
                    $cancelQuery = "UPDATE evaluation_requests 
                                   SET status = 'cancelled', 
                                       updated_at = NOW()
                                   WHERE request_id = :request_id";
                    $cancelStmt = $db->prepare($cancelQuery);
                    $result = $cancelStmt->execute(['request_id' => $request_id]);
                    
                    if ($result) {
                        $success = "Request #$request_id has been successfully cancelled";
                        logSecurityEvent('REQUEST_CANCELLED', 
                            "User {$_SESSION['email']} cancelled request #$request_id");
                    } else {
                        $errors[] = "Failed to cancel request. Please try again.";
                    }
                }
            } catch (PDOException $e) {
                error_log("Cancel Request Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Handle delete request action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_request') {
    // CSRF protection
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = "Invalid security token. Please try again.";
        logSecurityEvent('DELETE_REQUEST_CSRF_FAILED', 'Invalid CSRF token');
    } else {
        $request_id = intval($_POST['request_id'] ?? 0);
        
        if ($request_id <= 0) {
            $errors[] = "Invalid request ID";
        } else {
            try {
                $database = new Database();
                $db = $database->getConnection();
                
                // Verify the request belongs to the current user and status is cancelled
                $checkQuery = "SELECT request_id, status, user_id, photo_filename FROM evaluation_requests 
                              WHERE request_id = :request_id";
                $checkStmt = $db->prepare($checkQuery);
                $checkStmt->execute(['request_id' => $request_id]);
                $requestData = $checkStmt->fetch();
                
                if (!$requestData) {
                    $errors[] = "Request not found";
                } else if ($requestData['user_id'] != $_SESSION['user_id']) {
                    $errors[] = "You don't have permission to delete this request";
                    logSecurityEvent('UNAUTHORIZED_DELETE_ATTEMPT', 
                        "User {$_SESSION['user_id']} tried to delete request belonging to user {$requestData['user_id']}");
                } else if ($requestData['status'] !== 'cancelled') {
                    $errors[] = "Only cancelled requests can be deleted. This request is '{$requestData['status']}'";
                } else {
                    // Delete the uploaded photo file if it exists
                    if (!empty($requestData['photo_filename'])) {
                        $photoPath = __DIR__ . '/uploads/' . $requestData['photo_filename'];
                        if (file_exists($photoPath)) {
                            unlink($photoPath);
                        }
                    }
                    
                    // Execute delete operation
                    $deleteQuery = "DELETE FROM evaluation_requests WHERE request_id = :request_id";
                    $deleteStmt = $db->prepare($deleteQuery);
                    $result = $deleteStmt->execute(['request_id' => $request_id]);
                    
                    if ($result) {
                        $success = "Request #$request_id has been permanently deleted";
                        logSecurityEvent('REQUEST_DELETED', 
                            "User {$_SESSION['email']} deleted cancelled request #$request_id");
                    } else {
                        $errors[] = "Failed to delete request. Please try again.";
                    }
                }
            } catch (PDOException $e) {
                error_log("Delete Request Error: " . $e->getMessage());
                $errors[] = "An error occurred. Please try again.";
            }
        }
    }
}

// Fetch user's evaluation requests
try {
    $database = new Database();
    $db = $database->getConnection();
    
    $query = "SELECT 
                request_id,
                object_description,
                contact_method,
                photo_filename,
                status,
                admin_notes,
                created_at,
                updated_at
              FROM evaluation_requests
              WHERE user_id = :user_id
              ORDER BY created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute(['user_id' => $_SESSION['user_id']]);
    $requests = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Fetch User Requests Error: " . $e->getMessage());
    $requests = [];
}

$user_name = $_SESSION['full_name'] ?? 'User';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Requests - Lovejoy's Antique Evaluation</title>
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
        
        .page-header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .page-header h2 {
            color: #333;
        }
        
        .btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 600;
            transition: transform 0.2s;
            display: inline-block;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .requests-grid {
            display: grid;
            gap: 20px;
        }
        
        .request-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
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
        
        .request-description {
            color: #666;
            line-height: 1.6;
            margin-bottom: 15px;
        }
        
        .request-meta {
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #999;
            border-top: 1px solid #e0e0e0;
            padding-top: 15px;
        }
        
        .request-meta div {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .admin-notes {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border-left: 3px solid #667eea;
        }
        
        .admin-notes h4 {
            color: #333;
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .admin-notes p {
            color: #666;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .no-requests {
            background: white;
            border-radius: 10px;
            padding: 60px 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .no-requests h3 {
            color: #333;
            font-size: 24px;
            margin-bottom: 15px;
        }
        
        .no-requests p {
            color: #666;
            margin-bottom: 25px;
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
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
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
        
        .alert ul {
            margin: 10px 0 0 20px;
        }
        
        .alert li {
            margin: 5px 0;
        }
        
        .request-actions {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
        }
        
        .btn-cancel {
            padding: 8px 16px;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 5px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s;
            font-size: 14px;
        }
        
        .btn-cancel:hover {
            background: #c82333;
        }
        
        .btn-cancel:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .btn-delete {
            padding: 8px 16px;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 5px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s;
            font-size: 14px;
        }
        
        .btn-delete:hover {
            background: #5a6268;
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
                <a href="request_evaluation.php">New Request</a>
                <a href="logout.php">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="page-header">
            <div>
                <h2>📋 My Evaluation Requests</h2>
                <p style="color: #666; margin-top: 5px;">Track the status of your submissions</p>
            </div>
            <a href="request_evaluation.php" class="btn">+ New Request</a>
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
        
        <?php if (empty($requests)): ?>
            <div class="no-requests">
                <h3>No Evaluation Requests Yet</h3>
                <p>You haven't submitted any evaluation requests. Start by submitting your first antique for evaluation.</p>
                <a href="request_evaluation.php" class="btn">Submit Your First Request</a>
            </div>
        <?php else: ?>
            <div class="requests-grid">
                <?php foreach ($requests as $request): ?>
                    <div class="request-card">
                        <div class="request-header">
                            <div class="request-id">
                                Request #<?php echo htmlspecialchars($request['request_id']); ?>
                            </div>
                            <div class="status-badge status-<?php echo htmlspecialchars($request['status']); ?>">
                                <?php echo htmlspecialchars(str_replace('_', ' ', $request['status'])); ?>
                            </div>
                        </div>
                        
                        <div class="request-description">
                            <?php echo nl2br(htmlspecialchars($request['object_description'])); ?>
                        </div>
                        
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
                        
                        <?php if (!empty($request['admin_notes'])): ?>
                            <div class="admin-notes">
                                <h4>Admin Notes:</h4>
                                <p><?php echo nl2br(htmlspecialchars($request['admin_notes'])); ?></p>
                            </div>
                        <?php endif; ?>
                        
                        <div class="request-meta">
                            <div>
                                <strong>Contact Method:</strong> 
                                <?php echo htmlspecialchars(ucfirst($request['contact_method'])); ?>
                            </div>
                            <div>
                                <strong>Submitted:</strong> 
                                <?php echo date('M d, Y H:i', strtotime($request['created_at'])); ?>
                            </div>
                            <?php if ($request['updated_at'] !== $request['created_at']): ?>
                                <div>
                                    <strong>Last Updated:</strong> 
                                    <?php echo date('M d, Y H:i', strtotime($request['updated_at'])); ?>
                                </div>
                            <?php endif; ?>
                        </div>
                        
                        <?php if ($request['status'] === 'pending'): ?>
                            <div class="request-actions">
                                <form method="POST" onsubmit="return confirm('Are you sure you want to cancel this evaluation request? This action cannot be undone.');" style="margin: 0;">
                                    <input type="hidden" name="action" value="cancel_request">
                                    <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request['request_id']); ?>">
                                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                    <button type="submit" class="btn-cancel">❌ Cancel Request</button>
                                </form>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($request['status'] === 'cancelled'): ?>
                            <div class="request-actions">
                                <form method="POST" onsubmit="return confirm('Are you sure you want to permanently delete this request? This action cannot be undone and all associated data including photos will be deleted.');" style="margin: 0;">
                                    <input type="hidden" name="action" value="delete_request">
                                    <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request['request_id']); ?>">
                                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                    <button type="submit" class="btn-delete">🗑️ Delete Request</button>
                                </form>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
    
    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
