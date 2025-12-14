-- ============================================================================
-- TASK 6: DATABASE DESIGN (5 marks)
-- Lovejoy's Antique Evaluation Database Setup
-- ============================================================================
-- Security Features:
-- 1. Proper normalization to prevent data redundancy
-- 2. Foreign key constraints for data integrity
-- 3. Indexes for performance optimization
-- 4. Audit logging table for security tracking
-- 5. Separate table for password reset tokens with expiration
-- ============================================================================

-- Drop existing database if exists (for clean installation)
DROP DATABASE IF EXISTS lovejoy_antiques_secure;

-- Create database with UTF-8 support
CREATE DATABASE lovejoy_antiques_secure CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE lovejoy_antiques_secure;

-- ============================================================================
-- TABLE: users
-- Stores user account information with secure password hashing
-- ============================================================================
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    role ENUM('customer', 'admin') DEFAULT 'customer' NOT NULL,
    account_status ENUM('active', 'locked', 'pending') DEFAULT 'active' NOT NULL,
    failed_login_attempts INT DEFAULT 0,
    last_login DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_role (role),
    INDEX idx_account_status (account_status)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE: password_reset_tokens
-- Stores password reset tokens with expiration for security
-- ============================================================================
CREATE TABLE password_reset_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE: evaluation_requests
-- Stores evaluation requests submitted by customers
-- ============================================================================
CREATE TABLE evaluation_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    object_description TEXT NOT NULL,
    contact_method ENUM('email', 'phone') NOT NULL,
    photo_filename VARCHAR(255) NULL,
    status ENUM('pending', 'in_progress', 'completed', 'cancelled') DEFAULT 'pending' NOT NULL,
    admin_notes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE: audit_log
-- Security audit trail for tracking important actions
-- ============================================================================
CREATE TABLE audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    details TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE: user_sessions
-- Enhanced session management for security
-- ============================================================================
CREATE TABLE user_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_last_activity (last_activity)
) ENGINE=InnoDB;

-- ============================================================================
-- INITIAL DATA: Test Accounts
-- ============================================================================

-- Admin Account
-- Email: admin@lovejoy.com
-- Password: Admin@Secure2025!
INSERT INTO users (email, password_hash, full_name, phone_number, role, account_status) 
VALUES (
    'admin@lovejoy.com', 
    '$2y$12$0.YVUWomHNEYmrlxJzNccejD.dQEOwY4mG7BX1QQaAvMcpj1gJ7u6',
    'Administrator',
    '+44-20-1234-5678',
    'admin',
    'active'
);

-- Test Customer Account 1
-- Email: john.antique@example.com
-- Password: JohnAntique@2025!
INSERT INTO users (email, password_hash, full_name, phone_number, role, account_status) 
VALUES (
    'john.antique@example.com', 
    '$2y$12$w/ByMXSJKsnvIF9mhe6qIe/DmhRIPWzDpg3sZYNf4h4zDb3EGs7Ia',
    'John Antique Collector',
    '+44-161-555-1234',
    'customer',
    'active'
);

-- Test Customer Account 2
-- Email: mary.vintage@example.com
-- Password: MaryVintage@2025!
INSERT INTO users (email, password_hash, full_name, phone_number, role, account_status) 
VALUES (
    'mary.vintage@example.com', 
    '$2y$12$5GX2eH2F6oV.tBL8FbmT1O41w1wephVtSCeHGXbdMaB2hSATDN09.',
    'Mary Vintage Enthusiast',
    '+44-121-555-5678',
    'customer',
    'active'
);

-- Insert sample evaluation requests for demonstration
INSERT INTO evaluation_requests (user_id, object_description, contact_method, photo_filename, status) 
VALUES 
(2, 'Victorian-era pocket watch with gold chain. Appears to be in good condition with minimal wear.', 'email', 'pocket_watch_001.jpg', 'pending'),
(3, 'Antique mahogany writing desk, estimated 1850s. Has some surface scratches but structurally sound.', 'phone', 'writing_desk_001.jpg', 'in_progress'),
(2, 'Chinese porcelain vase with blue and white patterns. Height approximately 12 inches.', 'email', 'vase_001.jpg', 'completed');

-- ============================================================================
-- DATABASE DESIGN SUMMARY
-- ============================================================================
-- 
-- Security Features:
-- 1. All passwords stored with bcrypt hashing (cost factor 12)
-- 2. Foreign key constraints ensure data integrity
-- 3. Indexes optimize query performance
-- 4. Audit logging tracks all security-relevant actions
-- 5. Password reset tokens have expiration mechanism
-- 6. User sessions tracked with IP and user agent for security
-- 
-- Table Relationships:
-- - users (1) -> evaluation_requests (many)
-- - users (1) -> password_reset_tokens (many)
-- - users (1) -> user_sessions (many)
-- - users (1) -> audit_log (many)
-- 
-- ============================================================================
