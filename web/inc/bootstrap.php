<?php
declare(strict_types=1);

$storageDir = dirname(__DIR__) . '/storage';
if (!is_dir($storageDir)) {
    @mkdir($storageDir, 0750, true);
}
if (is_dir($storageDir) && is_writable($storageDir)) {
    ini_set('log_errors', '1');
    ini_set('error_log', $storageDir . '/php-errors.log');
}
ini_set('display_errors', '0');

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    exit('Для сайта требуется PHP 8.1 или новее.');
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");

$configPath = dirname(__DIR__) . '/config.php';
if (!is_file($configPath)) {
    header('Location: setup.php', true, 302);
    exit;
}
if (!is_readable($configPath)) {
    http_response_code(500);
    exit('Файл config.php недоступен для чтения.');
}

try {
    $config = require $configPath;
} catch (Throwable $e) {
    error_log('Config load error: ' . $e->getMessage());
    http_response_code(500);
    exit('Не удалось прочитать config.php.');
}

if (!is_array($config) || empty($config['installed']) || empty($config['db']) || empty($config['public_base_url']) || empty($config['app_key'])) {
    header('Location: setup.php', true, 302);
    exit;
}

date_default_timezone_set((string)($config['timezone'] ?? 'Europe/Samara'));
if (strncmp(strtolower((string)$config['public_base_url']), 'https://', 8) === 0) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name((string)($config['session_name'] ?? 'robot_delivery_session'));
    $https = strncmp(strtolower((string)$config['public_base_url']), 'https://', 8) === 0;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

if (isset($_SESSION['last_activity']) && time() - (int)$_SESSION['last_activity'] > 28800) {
    $_SESSION = [];
    session_destroy();
    session_start();
}
$_SESSION['last_activity'] = time();
if (!isset($_SESSION['last_regeneration']) || time() - (int)$_SESSION['last_regeneration'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

if (!extension_loaded('pdo_mysql') || !extension_loaded('openssl')) {
    http_response_code(500);
    exit('Требуются расширения pdo_mysql и openssl.');
}

$dbConfig = $config['db'];
$dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=%s', $dbConfig['host'], $dbConfig['port'], $dbConfig['name'], $dbConfig['charset'] ?? 'utf8mb4');
try {
    $pdo = new PDO($dsn, $dbConfig['user'], $dbConfig['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $e) {
    error_log('Database connection error: ' . $e->getMessage());
    http_response_code(500);
    exit('Не удалось подключиться к MySQL.');
}

require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/views.php';
