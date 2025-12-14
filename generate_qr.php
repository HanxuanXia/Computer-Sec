<?php
/**
 * Local QR Code Generator
 * Uses phpqrcode library to generate QR codes on the server side
 * No dependency on external APIs (like Google Chart API)
 */

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 0); // Don't display errors in image output
ini_set('log_errors', 1);

// Check if phpqrcode library exists
if (!file_exists(__DIR__ . '/phpqrcode/qrlib.php')) {
    header('HTTP/1.1 500 Internal Server Error');
    error_log("QR Generator Error: phpqrcode library not found");
    die('Error: QR code library not found');
}

require_once __DIR__ . '/phpqrcode/qrlib.php';

// Get parameters from URL
$secret = isset($_GET['secret']) ? $_GET['secret'] : '';
$email = isset($_GET['email']) ? $_GET['email'] : '';
$issuer = isset($_GET['issuer']) ? $_GET['issuer'] : "Lovejoy's Antiques";

if (empty($secret) || empty($email)) {
    header('HTTP/1.1 400 Bad Request');
    error_log("QR Generator Error: Missing parameters - secret: " . (empty($secret) ? 'empty' : 'ok') . ", email: " . (empty($email) ? 'empty' : 'ok'));
    die('Error: Missing required parameters (secret and email)');
}

try {
    // Create TOTP URI
    $issuer_encoded = urlencode($issuer);
    $email_encoded = urlencode($email);
    $otpUri = "otpauth://totp/{$issuer_encoded}:{$email_encoded}?secret={$secret}&issuer={$issuer_encoded}";
    
    // Log the URI for debugging
    error_log("QR Generator: Generating QR for URI: " . $otpUri);
    
    // Set headers for PNG image
    header('Content-Type: image/png');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Generate QR code and output directly as PNG
    // Parameters: data, filename (null for direct output), error correction level, size, margin
    QRcode::png($otpUri, null, QR_ECLEVEL_L, 6, 2);
    
} catch (Exception $e) {
    error_log("QR Generator Exception: " . $e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    die('Error generating QR code');
}

