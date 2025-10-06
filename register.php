<?php
// register.php
require_once 'db.php';
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php'); exit;
}

// CSRF token check
$token = $_POST['csrf_token'] ?? '';
if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
    audit_log($pdo, 'csrf_failure', 'CSRF token mismatch on registration', null);
    die('Invalid request.');
}

// sanitize inputs
$username = sanitize_input($_POST['username'] ?? '');
$email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
$password = $_POST['password'] ?? '';
$captcha_answer = sanitize_input($_POST['captcha_answer'] ?? '');

// basic server-side validation
$errors = [];
if (!validate_username($username)) $errors[] = 'Invalid username.';
if (!validate_email($email)) $errors[] = 'Invalid email.';
if (!validate_password($password)) $errors[] = 'Invalid password (min 8 chars, include upper/lower/digit).';

// CAPTCHA
$expected = ($_SESSION['captcha_a'] ?? 0) + ($_SESSION['captcha_b'] ?? 0);
if (!ctype_digit($captcha_answer) || intval($captcha_answer) !== intval($expected)) {
    $errors[] = 'Incorrect CAPTCHA.';
}

// suspicious input check
if (is_suspicious_input($username) || is_suspicious_input($email)) {
    audit_log($pdo, 'suspicious_registration', "Suspicious patterns in registration: username=$username email=$email", $username);
    $errors[] = 'Suspicious input detected.';
}

if ($errors) {
    // show first error (in production redirect with flash messages)
    die('Error: ' . htmlspecialchars($errors[0]));
}

try {
    // hash password (correct usage)
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
    $stmt->execute([$username, $email, $hash]);
    // registration success
    audit_log($pdo, 'registration', "New user registered", $username);
    echo 'Registration successful. You can now <a href="index.php">login</a>.';
} catch (PDOException $e) {
    // handle duplicate keys nicely
    if ($e->errorInfo[1] == 1062) {
        // duplicate entry
        audit_log($pdo, 'register_dup', 'Duplicate registration attempt: ' . $e->getMessage(), $username);
        die('Username or email already exists.');
    }
    audit_log($pdo, 'register_error', 'Registration DB error: ' . $e->getMessage(), $username);
    die('Registration failed.');
}
