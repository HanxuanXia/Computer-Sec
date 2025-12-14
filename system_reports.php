<?php
/**
 * SYSTEM REPORTS - Admin page to view system statistics and reports
 * Security: Admin-only access
 */

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/config/database.php';

// Require authentication and admin role
requireLogin();
requireAdmin();

// Fetch system statistics
try {
    $database = new Database();
    $db = $database->getConnection();
    
    // User statistics
    $userStatsQuery = "SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                        SUM(CASE WHEN role = 'customer' THEN 1 ELSE 0 END) as customer_count,
                        SUM(CASE WHEN account_status = 'active' THEN 1 ELSE 0 END) as active_users
                       FROM users";
    $userStatsStmt = $db->prepare($userStatsQuery);
    $userStatsStmt->execute();
    $userStats = $userStatsStmt->fetch();
    
    // Request statistics
    $requestStatsQuery = "SELECT 
                            COUNT(*) as total_requests,
                            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_requests,
                            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_requests,
                            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_requests,
                            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_requests
                          FROM evaluation_requests";
    $requestStatsStmt = $db->prepare($requestStatsQuery);
    $requestStatsStmt->execute();
    $requestStats = $requestStatsStmt->fetch();
    
    // Recent registrations (last 7 days)
    $recentUsersQuery = "SELECT COUNT(*) as count FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    $recentUsersStmt = $db->prepare($recentUsersQuery);
    $recentUsersStmt->execute();
    $recentUsers = $recentUsersStmt->fetch();
    
    // Recent requests (last 7 days)
    $recentRequestsQuery = "SELECT COUNT(*) as count FROM evaluation_requests WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    $recentRequestsStmt = $db->prepare($recentRequestsQuery);
    $recentRequestsStmt->execute();
    $recentRequests = $recentRequestsStmt->fetch();
    
    // Requests by status (for chart)
    $requestsByStatusQuery = "SELECT status, COUNT(*) as count FROM evaluation_requests GROUP BY status ORDER BY count DESC";
    $requestsByStatusStmt = $db->prepare($requestsByStatusQuery);
    $requestsByStatusStmt->execute();
    $requestsByStatus = $requestsByStatusStmt->fetchAll();
    
    // Top customers by request count
    $topCustomersQuery = "SELECT 
                            u.user_id,
                            u.full_name,
                            u.email,
                            COUNT(er.request_id) as request_count
                          FROM users u
                          LEFT JOIN evaluation_requests er ON u.user_id = er.user_id
                          WHERE u.role = 'customer'
                          GROUP BY u.user_id, u.full_name, u.email
                          HAVING request_count > 0
                          ORDER BY request_count DESC
                          LIMIT 10";
    $topCustomersStmt = $db->prepare($topCustomersQuery);
    $topCustomersStmt->execute();
    $topCustomers = $topCustomersStmt->fetchAll();
    
    // Recent activity (last 20 requests)
    $recentActivityQuery = "SELECT 
                                er.request_id,
                                er.status,
                                er.created_at,
                                er.updated_at,
                                u.full_name,
                                u.email
                            FROM evaluation_requests er
                            JOIN users u ON er.user_id = u.user_id
                            ORDER BY er.updated_at DESC
                            LIMIT 20";
    $recentActivityStmt = $db->prepare($recentActivityQuery);
    $recentActivityStmt->execute();
    $recentActivity = $recentActivityStmt->fetchAll();
    
    // Read security log (last 50 entries)
    $logFile = __DIR__ . '/logs/security.log';
    $securityLogs = [];
    if (file_exists($logFile)) {
        $logs = file($logFile, FILE_IGNORE_NEW_LINES);
        $securityLogs = array_slice(array_reverse($logs), 0, 50);
    }
    
} catch (PDOException $e) {
    error_log("System Reports Error: " . $e->getMessage());
    $userStats = null;
    $requestStats = null;
}

$user_name = $_SESSION['full_name'] ?? 'Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Reports - Lovejoy's Antiques</title>
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
            font-size: 36px;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            color: #666;
            font-size: 14px;
        }
        
        .stat-card.success h3 {
            color: #28a745;
        }
        
        .stat-card.warning h3 {
            color: #ffc107;
        }
        
        .stat-card.danger h3 {
            color: #dc3545;
        }
        
        .report-section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .report-section h3 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
            color: #666;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-in_progress {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .badge-completed {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-cancelled {
            background: #f8d7da;
            color: #721c24;
        }
        
        .log-entry {
            padding: 8px 12px;
            background: #f8f9fa;
            border-left: 3px solid #667eea;
            margin-bottom: 8px;
            font-size: 13px;
            font-family: 'Courier New', monospace;
            color: #333;
            border-radius: 3px;
        }
        
        .chart-container {
            margin: 20px 0;
        }
        
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .bar-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .bar-label {
            min-width: 100px;
            font-weight: 500;
            color: #333;
        }
        
        .bar {
            flex: 1;
            background: #e9ecef;
            border-radius: 5px;
            height: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .bar-fill {
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 5px;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: 600;
            font-size: 13px;
        }
        
        .no-data {
            text-align: center;
            padding: 40px 20px;
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
            <h2>📊 System Reports & Analytics</h2>
            <p style="color: #666; margin-top: 5px;">Overview of system statistics and activity</p>
        </div>
        
        <!-- Overview Statistics -->
        <h3 style="color: #333; margin-bottom: 15px;">📈 Overview Statistics</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <h3><?php echo $userStats['total_users'] ?? 0; ?></h3>
                <p>Total Users</p>
            </div>
            <div class="stat-card">
                <h3><?php echo $requestStats['total_requests'] ?? 0; ?></h3>
                <p>Total Requests</p>
            </div>
            <div class="stat-card warning">
                <h3><?php echo $requestStats['pending_requests'] ?? 0; ?></h3>
                <p>Pending Requests</p>
            </div>
            <div class="stat-card success">
                <h3><?php echo $requestStats['completed_requests'] ?? 0; ?></h3>
                <p>Completed Requests</p>
            </div>
            <div class="stat-card">
                <h3><?php echo $recentUsers['count'] ?? 0; ?></h3>
                <p>New Users (7 days)</p>
            </div>
            <div class="stat-card">
                <h3><?php echo $recentRequests['count'] ?? 0; ?></h3>
                <p>New Requests (7 days)</p>
            </div>
        </div>
        
        <!-- Requests by Status Chart -->
        <div class="report-section">
            <h3>📊 Requests by Status</h3>
            <?php if (!empty($requestsByStatus)): ?>
                <div class="chart-container">
                    <div class="bar-chart">
                        <?php 
                        $maxCount = max(array_column($requestsByStatus, 'count'));
                        foreach ($requestsByStatus as $item): 
                            $percentage = ($maxCount > 0) ? ($item['count'] / $maxCount * 100) : 0;
                        ?>
                            <div class="bar-item">
                                <div class="bar-label"><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $item['status']))); ?></div>
                                <div class="bar">
                                    <div class="bar-fill" style="width: <?php echo $percentage; ?>%">
                                        <?php echo $item['count']; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php else: ?>
                <div class="no-data">No request data available</div>
            <?php endif; ?>
        </div>
        
        <!-- Top Customers -->
        <div class="report-section">
            <h3>👥 Top Customers by Request Count</h3>
            <?php if (!empty($topCustomers)): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Customer Name</th>
                            <th>Email</th>
                            <th>Total Requests</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $rank = 1; foreach ($topCustomers as $customer): ?>
                            <tr>
                                <td><strong>#<?php echo $rank++; ?></strong></td>
                                <td><?php echo htmlspecialchars($customer['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($customer['email']); ?></td>
                                <td><strong><?php echo $customer['request_count']; ?></strong></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="no-data">No customer data available</div>
            <?php endif; ?>
        </div>
        
        <!-- Recent Activity -->
        <div class="report-section">
            <h3>🔄 Recent Activity (Last 20 Requests)</h3>
            <?php if (!empty($recentActivity)): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Request ID</th>
                            <th>Customer</th>
                            <th>Status</th>
                            <th>Submitted</th>
                            <th>Last Updated</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentActivity as $activity): ?>
                            <tr>
                                <td><strong>#<?php echo $activity['request_id']; ?></strong></td>
                                <td>
                                    <?php echo htmlspecialchars($activity['full_name']); ?><br>
                                    <small style="color: #999;"><?php echo htmlspecialchars($activity['email']); ?></small>
                                </td>
                                <td>
                                    <span class="badge badge-<?php echo $activity['status']; ?>">
                                        <?php echo htmlspecialchars(str_replace('_', ' ', $activity['status'])); ?>
                                    </span>
                                </td>
                                <td><?php echo date('M d, Y H:i', strtotime($activity['created_at'])); ?></td>
                                <td><?php echo date('M d, Y H:i', strtotime($activity['updated_at'])); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="no-data">No activity data available</div>
            <?php endif; ?>
        </div>
        
        <!-- Security Log -->
        <div class="report-section">
            <h3>🔒 Recent Security Events (Last 50 entries)</h3>
            <?php if (!empty($securityLogs)): ?>
                <div style="max-height: 400px; overflow-y: auto;">
                    <?php foreach ($securityLogs as $log): ?>
                        <div class="log-entry"><?php echo htmlspecialchars($log); ?></div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="no-data">No security logs available</div>
            <?php endif; ?>
        </div>
    </div>
    
    <?php include __DIR__ . '/includes/tab_security.php'; ?>
</body>
</html>
