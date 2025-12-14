-- ============================================================================
-- PASSWORD HASH GENERATOR FOR TEST ACCOUNTS
-- ============================================================================
-- Use this to generate new password hashes if needed
-- Run this PHP script to get the hashes:
-- ============================================================================

<?php
/*
 * Password Hash Generator
 * 
 * To generate new password hashes, save this as generate_hashes.php
 * and run: php generate_hashes.php
 */

function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

// Test Account Passwords
$passwords = [
    'Admin Account' => 'Admin@Secure2025!',
    'John Customer' => 'JohnAntique@2025!',
    'Mary Customer' => 'MaryVintage@2025!',
];

echo "PASSWORD HASHES FOR DATABASE\n";
echo "================================\n\n";

foreach ($passwords as $name => $password) {
    $hash = hashPassword($password);
    echo "$name:\n";
    echo "  Password: $password\n";
    echo "  Hash: $hash\n\n";
}

echo "================================\n";
echo "Use these hashes in the INSERT statements\n";
?>

-- ============================================================================
-- CURRENT TEST ACCOUNT PASSWORDS (as specified in the application)
-- ============================================================================

-- ADMIN ACCOUNT
-- Email: admin@lovejoy.com
-- Password: Admin@Secure2025!
-- Note: The actual hash is generated at runtime, but here's the SQL to update it:

-- UPDATE users 
-- SET password_hash = '$2y$12$[generated_hash_here]'
-- WHERE email = 'admin@lovejoy.com';


-- CUSTOMER ACCOUNT 1
-- Email: john.antique@example.com
-- Password: JohnAntique@2025!
-- This password meets all requirements:
--   ✓ 17 characters long
--   ✓ Contains uppercase: J, A
--   ✓ Contains lowercase: o, h, n, a, n, t, i, q, u, e
--   ✓ Contains numbers: 2, 0, 2, 5
--   ✓ Contains special: @, !


-- CUSTOMER ACCOUNT 2
-- Email: mary.vintage@example.com
-- Password: MaryVintage@2025!
-- This password meets all requirements:
--   ✓ 18 characters long
--   ✓ Contains uppercase: M, V
--   ✓ Contains lowercase: a, r, y, i, n, t, a, g, e
--   ✓ Contains numbers: 2, 0, 2, 5
--   ✓ Contains special: @, !


-- ============================================================================
-- TO CREATE NEW TEST ACCOUNTS WITH CUSTOM PASSWORDS:
-- ============================================================================

-- 1. Generate password hash using PHP:
--    php -r "echo password_hash('YourPassword@2025!', PASSWORD_BCRYPT, ['cost' => 12]);"

-- 2. Insert into database:
--    INSERT INTO users (email, password_hash, full_name, phone_number, role) 
--    VALUES (
--        'newemail@example.com',
--        '[paste_generated_hash_here]',
--        'Full Name',
--        '+44-XXX-XXX-XXXX',
--        'customer'
--    );


-- ============================================================================
-- PASSWORD REQUIREMENTS (Task 3 Evidence)
-- ============================================================================

-- The application enforces the following password policy:
-- 
-- 1. Minimum 12 characters
-- 2. At least one uppercase letter (A-Z)
-- 3. At least one lowercase letter (a-z)
-- 4. At least one digit (0-9)
-- 5. At least one special character (@, #, $, %, &, *, !)
-- 
-- Examples of VALID passwords:
--   ✓ SecurePass@2025!
--   ✓ MyAntique#Item99
--   ✓ Lovejoy$Secure123
--   ✓ VintageCollector@2025
-- 
-- Examples of INVALID passwords:
--   ✗ password123 (no uppercase, no special char)
--   ✗ PASSWORD123 (no lowercase, no special char)
--   ✗ Password! (too short, no numbers)
--   ✗ Pass@123 (too short)


-- ============================================================================
-- VERIFY TEST ACCOUNTS IN DATABASE
-- ============================================================================

-- Run this query to see all test accounts (passwords will be hashed):
SELECT 
    user_id,
    email,
    full_name,
    phone_number,
    role,
    account_status,
    failed_login_attempts,
    created_at
FROM users
WHERE email IN (
    'admin@lovejoy.com',
    'john.antique@example.com',
    'mary.vintage@example.com'
);

-- Expected output:
-- | user_id | email                     | full_name              | role     | account_status |
-- |---------|---------------------------|------------------------|----------|----------------|
-- | 1       | admin@lovejoy.com         | Administrator          | admin    | active         |
-- | 2       | john.antique@example.com  | John Antique Collector | customer | active         |
-- | 3       | mary.vintage@example.com  | Mary Vintage Enthusiast| customer | active         |


-- ============================================================================
-- PASSWORD STRENGTH TESTING
-- ============================================================================

-- Test these passwords in the registration form to see strength indicator:
-- 
-- WEAK passwords (will be rejected):
--   - "password" (no uppercase, no numbers, no special chars)
--   - "Pass123" (too short)
--   - "PASSWORD@" (no lowercase, no numbers)
-- 
-- MODERATE passwords (will be accepted but show warning):
--   - "Password@123" (exactly meets minimum requirements)
--   - "Secure123!@#" (13 characters, all requirements)
-- 
-- STRONG passwords (recommended):
--   - "SuperSecure@Password2025!" (27 characters)
--   - "Lovejoy#Antique$Dealer99!" (26 characters)
--   - "VintageCollection@2025!Secure" (30 characters)


-- ============================================================================
