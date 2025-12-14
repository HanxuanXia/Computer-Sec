<?php
/**
 * LOGOUT - Secure session termination
 * 
 * Security Features:
 * 1. Complete session destruction
 * 2. Cookie deletion
 * 3. Audit logging
 */

require_once __DIR__ . '/includes/security.php';

// Log the logout event
if (isset($_SESSION['email'])) {
    logSecurityEvent('USER_LOGOUT', 'User logged out: ' . $_SESSION['email']);
}

// Destroy all session data
session_unset();
session_destroy();

// Delete session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Redirect to login page
header('Location: login.php?message=logged_out');
exit();
?>
