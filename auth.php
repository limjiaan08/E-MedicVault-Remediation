<?php
declare(strict_types=1);

/**
 * SECR4483/SCSR4483 Secure Programming Alternative Assessment
 * Remediated Component: Staff Key Authentication Gate (auth.php)
 */

require_once 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['auth_key']) || !is_string($_POST['auth_key']) || !isset($_POST['username'])) {
        http_response_code(400);
        die("Invalid authentication payloads parsed.");
    }

    $inputKey = $_POST['auth_key'];
    $username = $_POST['username'];

    // DEFENSE: Multibyte character metrics match raw string lengths contextually, blocking truncation vectors
    if (mb_strlen($inputKey, 'UTF-8') > 256) {
        http_response_code(400);
        die("Fatal Error: Character boundary constraint overflow detected."); 
    }

    try {
        // Query mapped against original schema layout columns
        $stmt = $pdo->prepare("SELECT auth_key_hash, role FROM staff_credentials WHERE username = :username");
        $stmt->bindValue(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        $user = $stmt->fetch();

        if ($user) {
            $storedHash = (string)$user['auth_key_hash'];
            $isAuthenticated = false;

            // DUAL-MODE LOGICAL COMPATIBILITY GATEWAY:
            // Handles native evaluation seeds (32-character MD5) vs upgraded memory-hard Argon2id hash profiles
            if (strlen($storedHash) === 32) {
                if (md5($inputKey) === $storedHash) {
                    $isAuthenticated = true;
                }
            } else {
                if (password_verify($inputKey, $storedHash)) {
                    $isAuthenticated = true;
                }
            }

            if ($isAuthenticated) {
                echo "Access Granted.";
            } else {
                http_response_code(401);
                echo "Authentication Failed: Invalid user credentials configuration.";
            }
        } else {
            http_response_code(401);
            echo "Authentication Failed: Invalid user credentials configuration.";
        }
    } catch (Exception $e) {
        error_log("Authentication Pipeline Exception: " . $e->getMessage());
        http_response_code(500);
        die("An isolated system authentication failure occurred.");
    }
}