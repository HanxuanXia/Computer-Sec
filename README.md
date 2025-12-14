# 🏺 Lovejoy's Antique Evaluation System

A secure web application for antique evaluation and appraisal services with enterprise-grade security features.

## 📋 Project Overview

This is a secure web-based system that allows customers to submit antique items for professional evaluation. The system implements comprehensive security measures to protect user data and prevent common web vulnerabilities.

**Course**: Computer Security  
**Institution**: University of Sussex  
**Developer**: Hanxuan Xia

---

## ✨ Key Features

### 🔐 Security Features Implemented

- ✅ **SQL Injection Prevention** - PDO prepared statements
- ✅ **XSS Prevention** - Input sanitization and output encoding
- ✅ **CSRF Protection** - Token-based validation
- ✅ **Session Hijacking Prevention** - Secure session configuration
- ✅ **Brute Force Protection** - Rate limiting and account lockout
- ✅ **Two-Factor Authentication** - TOTP with Google Authenticator
- ✅ **Email Verification** - 6-digit verification codes
- ✅ **Password Security** - Bcrypt hashing with cost factor 12
- ✅ **File Upload Validation** - Type, size, and content verification
- ✅ **Audit Logging** - Security event tracking
- ✅ **Google reCAPTCHA** - Bot protection
- ✅ **Role-Based Access Control** - Admin/Customer roles

### 👥 User Roles

1. **Customer** - Submit evaluation requests, upload images, view results
2. **Admin** - Review requests, manage users, view system reports

### 📱 Two-Factor Authentication

- TOTP-based (compatible with Google Authenticator, Authy)
- Local QR code generation using phpqrcode library
- Backup codes for account recovery
- Manual key entry option

---

## 🚀 Quick Start

### Prerequisites
- PHP 8.0+
- MySQL 5.7+
- Apache/Nginx
- Composer

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/HanxuanXia/Computer-Sec.git
   cd Computer-Sec
   ```

2. **Install dependencies**
   ```bash
   composer install
   ```

3. **Configure database**
   ```bash
   # Import SQL files
   mysql -u root -p your_database < config/database_setup.sql
   mysql -u root -p your_database < config/security_features_migration.sql
   mysql -u root -p your_database < config/email_verification_setup.sql
   ```

4. **Update configuration**
   - Edit `config/database.php` with your DB credentials
   - Edit `config/security_config.php` with your settings

5. **Set permissions**
   ```bash
   chmod 755 uploads/
   chmod 755 phpqrcode/cache/
   chmod 755 phpqrcode/temp/
   ```

---

## 📂 Project Structure

```
lovejoy_secure_app/
├── config/           # Configuration files
├── includes/         # Core security & functionality
├── css/             # Stylesheets
├── js/              # JavaScript
├── phpqrcode/       # QR code library
├── uploads/         # User uploads
├── vendor/          # Composer dependencies
└── *.php           # Application pages
```

---

## 🔒 Security Implementation

### SQL Injection Prevention
```php
$stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $email]);
```

### XSS Prevention
```php
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}
```

### CSRF Protection
```php
$csrf_token = generateCSRFToken();
verifyCSRFToken($_POST['csrf_token']);
```

### Password Hashing
```php
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
```

### Session Security
```php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
```

---

## 🧪 Test Accounts

**Admin:**
- Email: `admin@lovejoy.com`
- Password: `Admin123456!`
- 2FA: Enabled

**Customer:**
- Email: `customer@lovejoy.com`
- Password: `Customer123456!`

---

## 🛡️ Security Checklist

- [x] Input validation on all forms
- [x] Output encoding to prevent XSS
- [x] Prepared statements for SQL queries
- [x] CSRF tokens on all forms
- [x] Secure session configuration
- [x] Password strength requirements (12+ chars)
- [x] Rate limiting on login/registration
- [x] Account lockout after failed attempts
- [x] Two-factor authentication
- [x] Email verification
- [x] File upload validation
- [x] Audit logging
- [x] HTTPS-ready configuration

---

**Last Updated**: December 14, 2025
