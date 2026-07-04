<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../crypto_vault.php';

/**
 * SECR4483/SCSR4483 Secure Programming Automated Diagnostic Test Suite
 * Comprehensive Forensic & Remediated Architecture Verification
 */
class CryptoVaultTest extends TestCase
{
    private string $secureKey;
    private string $mockAssociatedData;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->secureKey = base64_decode("MmY0YTViNmM3ZDhlOWYxYTI2Y3MxMjM0bW9oZGt1ZmFpc2FsOTg3NjU0");
        $this->mockAssociatedData = "MediChain_E_MedicVault_Context_2026";
        
        putenv("CRYPTO_VAULT_KEY=MmY0YTViNmM3ZDhlOWYxYTI2Y3MxMjM0bW9oZGt1ZmFpc2FsOTg3NjU0");
    }

    /** @test */
    public function testUntamperedCryptographicLifecyclePassesCleanly(): void
    {
        $sensitiveMedicalPayload = "PATIENT_ID: 950403-01-5543 | DOSAGE: OPIOID 50MG | STATUS: CRITICAL";
        
        $ivLength = openssl_cipher_iv_length('aes-256-gcm');
        $dynamicIv = openssl_random_pseudo_bytes($ivLength, $isStrong);
        $this->assertTrue($isStrong);

        $tag = ''; 

        $ciphertext = openssl_encrypt(
            $sensitiveMedicalPayload, 'aes-256-gcm', $this->secureKey, OPENSSL_RAW_DATA,
            $dynamicIv, $tag, $this->mockAssociatedData, 16
        );
        $this->assertNotFalse($ciphertext);

        $serializedStream = $dynamicIv . $tag . $ciphertext;
        $encodedToken = base64_encode($serializedStream);
        
        // Decryption lifecycle verification
        $recoveredPlaintext = decrypt_medical_record($encodedToken);
        $this->assertEquals($sensitiveMedicalPayload, $recoveredPlaintext);
    }

    /** @test */
    public function testTamperedCiphertextFailsIntegrityCheckAndThrowsException(): void
    {
        $confidentialData = "DIAGNOSIS: Stage-2 Carcinoma. TREATMENT: Chemotherapy cycle 1.";
        
        $ivLength = openssl_cipher_iv_length('aes-256-gcm');
        $dynamicIv = openssl_random_pseudo_bytes($ivLength);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $confidentialData, 'aes-256-gcm', $this->secureKey, OPENSSL_RAW_DATA,
            $dynamicIv, $tag, $this->mockAssociatedData, 16
        );

        // Attack Simulation: Perform standard bitwise in-flight modification manipulation
        $ciphertext[5] = $ciphertext[5] ^ "\x01"; 
        $tamperedSerializedStream = $dynamicIv . $tag . $ciphertext;
        $encodedTamperedToken = base64_encode($tamperedSerializedStream);

        // Assert that the engine isolates the tag mismatch exception and safely drops processing
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Cryptographic Integrity Violation");
        
        decrypt_medical_record($encodedTamperedToken);
    }

    /** @test */
    public function testCredentialHashIntegrityMatchesArgon2idParameters(): void
    {
        $staffSecretKey = "doctorsecret";

        $computedSecureHash = password_hash($staffSecretKey, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB operational memory boundary
            'time_cost'   => 4,     // 4 iteration loops
            'threads'     => 2      // 2 parallel parsing paths
        ]);

        $hashAnalysisMetadata = password_get_info($computedSecureHash);

        $this->assertEquals('argon2id', $hashAnalysisMetadata['algoName']);
        $this->assertTrue(password_verify($staffSecretKey, $computedSecureHash));
    }
}