<?php
/**
 * Logout endpoint for new tab detection
 * Destroys the session when user opens a new tab
 */

require_once __DIR__ . '/includes/security.php';

// Destroy the session
session_unset();
session_destroy();

// Return success
header('Content-Type: application/json');
echo json_encode(['success' => true, 'message' => 'Session destroyed']);
exit();
