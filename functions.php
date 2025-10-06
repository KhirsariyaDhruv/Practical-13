<?php
if (session_status() === PHP_SESSION_NONE) {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_start();
}

function sanitize_input(string $str): string {
    $s = trim($str);
    $s = preg_replace('/[\x00-\x1F\x7F]/u', '', $s);
    $s = preg_replace('/\s{2,}/u', ' ', $s);
    return $s;
}

function esc(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function validate_username(string $u): bool {
    return (bool) preg_match('/^[A-Za-z0-9_.]{3,30}$/', $u);
}

function validate_email(string $e): bool {
    return (bool) filter_var($e, FILTER_VALIDATE_EMAIL);
}

function validate_password(string $p): bool {
    return (bool) preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $p);
}

function get_client_ip(): string {
    $ip_keys = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];
            if (strpos($ip, ',') !== false) {
                $parts = array_map('trim', explode(',', $ip));
                $ip = $parts[0];
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function audit_log($pdo = null, string $event_type, string $message, ?string $username = null): void {
    $ip = get_client_ip();
    $time = date('Y-m-d H:i:s');
    if ($pdo instanceof PDO) {
        try {
            $stmt = $pdo->prepare("INSERT INTO audit_logs (event_time, ip, username, event_type, message) VALUES (NOW(), ?, ?, ?, ?)");
            $stmt->execute([$ip, $username, $event_type, $message]);
            return;
        } catch (Throwable $e) {
            error_log("AUDIT_LOG DB FAIL: " . $e->getMessage());
        }
    }
    $logLine = sprintf("[%s] %s | ip=%s | user=%s | type=%s | %s\n",
        $time,
        gethostname() !== false ? gethostname() : 'host',
        $ip,
        $username ?? '-',
        $event_type,
        $message
    );
    @file_put_contents(__DIR__ . '/audit_fallback.log', $logLine, FILE_APPEND | LOCK_EX);
}

function is_suspicious_input(string $str): bool {
    if ($str === '') return false;
    $patterns = [
        '/\bUNION\b/i',
        '/\bSELECT\b/i',
        '/\bINSERT\b/i',
        '/\bUPDATE\b/i',
        '/\bDELETE\b/i',
        '/\bDROP\b/i',
        '/--/',
        '/;/',
        '/\bOR\b\s+1=1/i',
        '/\bAND\b\s+1=1/i',
        '/\/\*/',
        '/\bSLEEP\(/i'
    ];
    foreach ($patterns as $p) {
        if (preg_match($p, $str)) {
            return true;
        }
    }
    return false;
}

function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(string $token): bool {
    if (empty($_SESSION['csrf_token'])) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}
