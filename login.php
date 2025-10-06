<?php
// login.php
require_once 'db.php';
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php'); exit;
}

// CSRF
$token = $_POST['csrf_token'] ?? '';
if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
    audit_log($pdo, 'csrf_failure', 'CSRF token mismatch on login', null);
    die('Invalid request.');
}

$user = sanitize_input($_POST['user'] ?? '');
$password = $_POST['password'] ?? '';

// suspicious input check
if (is_suspicious_input($user)) {
    audit_log($pdo, 'suspicious_login', "Suspicious login input: $user", $user);
    // continue, but we'll not reveal details to user
}

// find user by username OR email
try {
    $stmt = $pdo->prepare("SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1");
    $stmt->execute([$user, $user]);
    $row = $stmt->fetch();
    if (!$row) {
        audit_log($pdo, 'login_failed', "Login failed: unknown user", $user);
        die('Invalid credentials.');
    }
    if (!password_verify($password, $row['password_hash'])) {
        audit_log($pdo, 'login_failed', "Login failed: bad password for user {$row['username']}", $row['username']);
        die('Invalid credentials.');
    }
    // Optional: rehash if algorithm changed
    if (password_needs_rehash($row['password_hash'], PASSWORD_DEFAULT)) {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        $uStmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $uStmt->execute([$newHash, $row['id']]);
    }
    // success: set session
    session_regenerate_id(true);
    $_SESSION['user_id'] = $row['id'];
    $_SESSION['username'] = $row['username'];
    audit_log($pdo, 'login_success', "User logged in", $row['username']);
    echo "Login successful. Hello, " . htmlspecialchars($row['username']) . ".";
} catch (Exception $e) {
    audit_log($pdo, 'login_error', 'Login error: ' . $e->getMessage(), $user);
    die('Login failed.');
}
