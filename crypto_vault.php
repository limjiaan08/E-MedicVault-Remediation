<?php
declare(strict_types=1);

/**
 * SECR4483/SCSR4483 Secure Programming Alternative Assessment
 * Remediated Component: Patient Medical Records Symmetry Protection Suite (crypto_vault.php)
 */

require_once 'db_config.php';

// Upgraded condition handles both CLI runner execution and incoming HTTP server parameters safely
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!isset($_POST['payload']) || !is_string($_POST['payload'])) {
        http_response_code(400);
        die(json_encode(["error" => "Payload structural validation boundary failure."]));
    }

    $medical_payload = $_POST['payload'];
    
    // DEFENSE: Extraction of high-entropy base64 key variables from secure environmental space
    $secret_key = base64_decode((string)getenv('CRYPTO_VAULT_KEY'));
    if (strlen($secret_key) !== 32) { 
        http_response_code(500);
        die(json_encode(["error" => "Cryptographic operational key deployment anomaly."]));
    }

    // DEFENSE: Enforce random non-predictable dynamic states via cryptographically secure pseudo-random bytes
    $iv_length = openssl_cipher_iv_length('aes-256-gcm');
    $iv = openssl_random_pseudo_bytes($iv_length, $crypto_strong);
    if (!$crypto_strong) {
        http_response_code(500);
        die(json_encode(["error" => "Insufficient system core entropy states encountered."]));
    }

    $tag = ''; // Explicit bound reference capture buffer for the 16-byte authentication tag
    $associated_data = "MediChain_E_MedicVault_Context_2026";
    
    $ciphertext = openssl_encrypt(
        $medical_payload,
        'aes-256-gcm',
        $secret_key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        $associated_data,
        16 // Standard 16-byte tag tracking constraint
    );

    if ($ciphertext === false) {
        http_response_code(500);
        die(json_encode(["error" => "Encryption pipeline processing system failure."]));
    }

    // LOW-LEVEL BINARY SERIALIZATION PACKING: IV (12 Bytes) . Tag (16 Bytes) . Ciphertext
    $binary_serialized_stream = $iv . $tag . $ciphertext;
    $encoded_packed_string = base64_encode($binary_serialized_stream);

    header('Content-Type: application/json');
    echo json_encode([
        "status" => "vaulted", 
        "data" => $encoded_packed_string
    ]);
}

/**
 * Remediated Decryption Router Utility
 * Performs inverse deserialization and handles tag mismatches cleanly via safe error loops
 */
function decrypt_medical_record(string $encoded_packed_string): string {
    $secret_key = base64_decode((string)getenv('CRYPTO_VAULT_KEY'));
    $associated_data = "MediChain_E_MedicVault_Context_2026";
    
    $raw_binary = base64_decode($encoded_packed_string);
    
    $iv_len  = 12;
    $tag_len = 16;
    
    if (strlen($raw_binary) < ($iv_len + $tag_len)) {
        throw new Exception("Decryption Boundary Failure: Truncated crypto token stream.");
    }
    
    // LOW-LEVEL DESERIALIZATION UNPACKING: Slice stream by dynamic byte pointers
    $iv         = substr($raw_binary, 0, $iv_len);
    $tag        = substr($raw_binary, $iv_len, $tag_len);
    $ciphertext = substr($raw_binary, $iv_len + $tag_len);
    
    $decrypted = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $secret_key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        $associated_data
    );
    
    if ($decrypted === false) {
        // DEFENSE: Active error isolation prevents padding oracle profiling attacks
        throw new Exception("Cryptographic Integrity Violation: Authentication tag mismatch or altered data payload.");
    }
    
    return $decrypted;
}