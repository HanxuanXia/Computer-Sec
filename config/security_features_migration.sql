-- ============================================================================
-- SECURITY FEATURES MIGRATION
-- Add support for 2FA, Email Verification, and reCAPTCHA
-- ============================================================================
-- Run this script to add advanced security features to existing database
-- ============================================================================

USE lovejoy_antiques_secure;

-- Add 2FA and Email Verification columns to users table
ALTER TABLE users 
ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE AFTER account_status,
ADD COLUMN two_factor_secret VARCHAR(32) NULL AFTER two_factor_enabled,
ADD COLUMN email_verified BOOLEAN DEFAULT FALSE AFTER two_factor_secret,
ADD COLUMN email_verification_token VARCHAR(255) NULL AFTER email_verified,
ADD COLUMN email_verification_expires DATETIME NULL AFTER email_verification_token,
ADD INDEX idx_two_factor_enabled (two_factor_enabled),
ADD INDEX idx_email_verified (email_verified);

-- ============================================================================
-- TABLE: two_factor_backup_codes
-- Stores backup codes for 2FA recovery
-- ============================================================================
CREATE TABLE IF NOT EXISTS two_factor_backup_codes (
    code_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_used (used)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE: recaptcha_scores
-- Stores reCAPTCHA v3 scores for analysis and rate limiting
-- ============================================================================
CREATE TABLE IF NOT EXISTS recaptcha_scores (
    score_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL,
    score DECIMAL(3,2) NOT NULL,
    success BOOLEAN NOT NULL,
    hostname VARCHAR(255) NULL,
    challenge_ts DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_address (ip_address),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- Update existing users to have email_verified = TRUE if they are already active
-- (For migration purposes - existing users are considered verified)
UPDATE users 
SET email_verified = TRUE 
WHERE account_status = 'active';

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
-- Next steps:
-- 1. Update config/database.php with reCAPTCHA keys
-- 2. Install required libraries: composer require pragmarx/google2fa
-- 3. Enable features in register.php and login.php
-- ============================================================================

SELECT 'Security features migration completed successfully!' AS status;
