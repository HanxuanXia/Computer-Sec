<?php
/**
 * Database Configuration for Lovejoy's Antique Evaluation Application
 * 
 * Security Features:
 * 1. PDO with prepared statements to prevent SQL injection
 * 2. Error mode set to exception for proper error handling
 * 3. Emulate prepares disabled for true prepared statements
 * 4. UTF-8 character encoding to prevent character encoding attacks
 * 5. Connection errors logged securely without exposing sensitive details
 */

class Database {
    // Database credentials
    private $host = "localhost";
    private $db_name = "lovejoy_antiques_secure";
    private $username = "root";
    private $password = "";
    private $conn;

    /**
     * Get database connection with security configurations
     * 
     * @return PDO|null Database connection object
     */
    public function getConnection() {
        $this->conn = null;

        try {
            // Create PDO connection with security options
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->db_name . ";charset=utf8mb4",
                $this->username,
                $this->password,
                array(
                    // Throw exceptions on errors for proper handling
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    // Disable emulated prepares for true prepared statements
                    PDO::ATTR_EMULATE_PREPARES => false,
                    // Set default fetch mode to associative array
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    // Disable persistent connections for security
                    PDO::ATTR_PERSISTENT => false
                )
            );
            
            // Set character encoding to UTF-8 to prevent encoding attacks
            $this->conn->exec("SET NAMES utf8mb4");
            
        } catch(PDOException $e) {
            // Log error securely without exposing details to user
            error_log("Database Connection Error: " . $e->getMessage());
            
            // Display generic error message to user
            die("Database connection failed. Please contact the system administrator.");
        }

        return $this->conn;
    }
    
    /**
     * Close database connection
     */
    public function closeConnection() {
        $this->conn = null;
    }
}
?>
