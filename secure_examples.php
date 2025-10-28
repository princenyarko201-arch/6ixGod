<?php
// secure_examples.php
// Example of safe parameterized queries in PHP using PDO.

$dsn = "sqlite::memory:"; // or "mysql:host=127.0.0.1;dbname=test"
try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)");
} catch (PDOException $e) {
    echo "DB error: " . $e->getMessage();
    exit;
}

function insertUser($pdo, $username, $email) {
    $stmt = $pdo->prepare("INSERT INTO users (username, email) VALUES (:username, :email)");
    $stmt->execute([':username' => $username, ':email' => $email]);
}

function findUserByUsername($pdo, $username) {
    $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

insertUser($pdo, 'bob', 'bob@example.org');
print_r(findUserByUsername($pdo, 'bob'));
?>