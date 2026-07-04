<?php
declare(strict_types=1);

/**
 * SECR4483/SCSR4483 Secure Programming Alternative Assessment
 * Remediated Component: Patient & Medical Record Search Proxy (search.php)
 */

require_once 'db_config.php'; 

if (!isset($_GET['keyword']) || !is_string($_GET['keyword'])) {
    http_response_code(400);
    die(json_encode(["error" => "Invalid or missing request parameter structure."]));
}

$keyword = $_GET['keyword'];

try {
    // DEFENSE: Parameterized query structure locks the template tree on the command plane before accepting user data
    $sql = "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :keyword";
    $stmt = $pdo->prepare($sql);
    
    // Bind data elements securely into their designated memory slots
    $searchParam = "%" . $keyword . "%";
    $stmt->bindValue(':keyword', $searchParam, PDO::PARAM_STR);
    $stmt->execute();
    
    $results = $stmt->fetchAll();
    
    if (count($results) > 0) {
        foreach ($results as $row) {
            // DEFENSE: Context-aware output escaping replaces active markup tokens with inert HTML entities
            $safeKeyword = htmlspecialchars($keyword, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $safeName    = htmlspecialchars((string)$row['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $safeHistory = htmlspecialchars((string)$row['illness_history'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            
            // Output format mirrors legacy lookups safely
            echo "Result found for keyword: " . $safeKeyword . "<br>";
            echo "Patient: " . $safeName . " | History: " . $safeHistory . "<br><hr>";
        }
    } else {
        echo "No records found for: " . htmlspecialchars($keyword, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
} catch (PDOException $e) {
    error_log("Database Execution Failure: " . $e->getMessage());
    http_response_code(500);
    echo "An internal data access error occurred.";
}