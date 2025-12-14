-- ============================================================================
-- EMAIL VERIFICATION CODE SYSTEM
-- Stores 6-digit verification codes for email verification during registration
-- ============================================================================

-- Create table for email verification codes
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    verification_code VARCHAR(6) NOT NULL,
    user_id INT NULL,
    expires_at DATETIME NOT NULL,
    attempts INT DEFAULT 0,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_code (verification_code),
    INDEX idx_expires (expires_at),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- Add foreign key constraint if users table exists
-- Note: user_id can be NULL initially (before user completes registration)
ALTER TABLE email_verification_codes 
ADD CONSTRAINT fk_verification_user 
FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;
