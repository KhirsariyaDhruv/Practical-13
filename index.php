<?php
// index.php
require_once 'functions.php';

// generate a simple math captcha if not set or on request
if (empty($_SESSION['captcha_a']) || isset($_GET['new_captcha'])) {
    $_SESSION['captcha_a'] = rand(1, 9);
    $_SESSION['captcha_b'] = rand(1, 9);
}
// Make sure to regenerate token if needed for CSRF — simple token:
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$captcha_q = $_SESSION['captcha_a'] . ' + ' . $_SESSION['captcha_b'] . ' = ?';
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Registration / Login</title>

<style>
:root {
  --bg: #f5f7fb;
  --card: #ffffff;
  --accent: #2563eb;
  --muted: #6b7280;
}

body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
  background: linear-gradient(180deg, #eef2ff 0%, var(--bg) 100%);
  padding: 40px;
  color: #111827;
}

.container {
  max-width: 700px;
  margin: 0 auto;
}

h1 { text-align:center; margin-bottom: 20px; }

.card {
  background: var(--card);
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 6px 24px rgba(16,24,40,0.06);
  margin-bottom: 24px;
}

label {
  display: block;
  margin-bottom: 12px;
  font-weight: 500;
}

input[type="text"], input[type="email"], input[type="password"], input[type="number"] {
  width: 100%;
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid #e6e9ef;
  box-sizing: border-box;
  margin-top: 6px;
  font-size: 14px;
}

.actions {
  display:flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 12px;
}

button {
  background: var(--accent);
  color: white;
  padding: 10px 16px;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;
}

button:hover {
  background: #1e40af;
}

a.btn-link {
  color: var(--accent);
  text-decoration: none;
  font-size: 14px;
}

a.btn-link:hover {
  text-decoration: underline;
}

small { color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<div class="container">
  <h1>Secure Registration & Login</h1>

  <div class="card">
    <h2>Register</h2>
    <form id="registerForm" action="register.php" method="post" novalidate>
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
      <label>Username
        <input name="username" id="reg_username" required maxlength="30" pattern="^[A-Za-z0-9_.]{3,30}$">
      </label>
      <label>Email
        <input name="email" id="reg_email" type="email" required maxlength="255">
      </label>
      <label>Password
        <input name="password" id="reg_password" type="password" required minlength="8">
        <small>Password: min 8 chars, one upper, one lower, one digit</small>
      </label>
      <label>CAPTCHA: <?php echo htmlspecialchars($captcha_q); ?>
        <input name="captcha_answer" id="captcha_answer" required inputmode="numeric" pattern="\d+">
      </label>
      <div class="actions">
        <button type="submit">Register</button>
        <a href="index.php?new_captcha=1" class="btn-link">New CAPTCHA</a>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>Login</h2>
    <form id="loginForm" action="login.php" method="post" novalidate>
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
      <label>Username or Email
        <input name="user" id="login_user" required maxlength="255">
      </label>
      <label>Password
        <input name="password" id="login_password" type="password" required>
      </label>
      <div class="actions">
        <button type="submit">Login</button>
      </div>
    </form>
  </div>

</div>

<script>
// Client-side validation
const usernameRegex = /^[A-Za-z0-9_.]{3,30}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

document.getElementById('registerForm').addEventListener('submit', function(e) {
  const u = document.getElementById('reg_username').value.trim();
  const eaddr = document.getElementById('reg_email').value.trim();
  const p = document.getElementById('reg_password').value;
  const cap = document.getElementById('captcha_answer').value.trim();

  if (!usernameRegex.test(u)) {
    alert('Username must be 3-30 chars: letters, numbers, underscores or dots.');
    e.preventDefault(); return;
  }
  if (!passwordRegex.test(p)) {
    alert('Password must be at least 8 chars with upper, lower, and digit.');
    e.preventDefault(); return;
  }
  if (!cap.match(/^\d+$/)) {
    alert('CAPTCHA answer must be a number.');
    e.preventDefault(); return;
  }
});

document.getElementById('loginForm').addEventListener('submit', function(e){
  const user = document.getElementById('login_user').value.trim();
  const p = document.getElementById('login_password').value;
  if (!user || !p) {
    alert('Enter username/email and password.');
    e.preventDefault();
  }
});
</script>
</body>
</html>
