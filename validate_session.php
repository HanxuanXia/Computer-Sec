<?php
/**
 * SESSION VALIDATION ENDPOINT
 * Validates if user's session is still active
 */

require_once __DIR__ . '/includes/security.php';

header('Content-Type: application/json');

$response = ['valid' => false];

// Check if user is logged in
if (isLoggedIn()) {
    $response['valid'] = true;
    $response['user_id'] = $_SESSION['user_id'];
    $response['email'] = $_SESSION['email'];
    $response['session_age'] = time() - ($_SESSION['created_at'] ?? time());
} else {
    $response['message'] = 'Session expired or invalid';
}

echo json_encode($response);
?>
