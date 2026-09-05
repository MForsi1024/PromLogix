<?php
declare(strict_types=1);

const TERMINAL_MISSION_STATUSES = ['completed', 'cancelled', 'failed'];
const ACTIVE_MISSION_STATUSES = [
    'created', 'edge_accepted', 'waiting_for_loading', 'start_requested',
    'moving_to_destination', 'arrived', 'waiting_auth', 'access_granted',
    'delivered', 'returning', 'cancel_requested'
];

function h(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function base_url(string $path = ''): string
{
    global $config;
    return rtrim((string)$config['public_base_url'], '/') . ($path === '' ? '' : '/' . ltrim($path, '/'));
}

function redirect_to(string $path): void
{
    header('Location: ' . base_url($path), true, 303);
    exit;
}

function request_path(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $scriptName = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/index.php');
    $base = rtrim(str_replace('/index.php', '', $scriptName), '/');
    if ($base !== '' && strncmp($path, $base, strlen($base)) === 0) {
        $path = substr($path, strlen($base));
    }
    $path = '/' . ltrim($path, '/');
    return $path === '//' ? '/' : (rtrim($path, '/') ?: '/');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
    }
    return (string)$_SESSION['csrf'];
}

function verify_csrf(): void
{
    $token = (string)($_POST['csrf'] ?? '');
    if ($token === '' || !hash_equals((string)($_SESSION['csrf'] ?? ''), $token)) {
        http_response_code(403);
        exit('Некорректный CSRF-токен. Вернитесь назад и повторите действие.');
    }
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function take_flashes(): array
{
    $items = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return is_array($items) ? $items : [];
}

function current_user(): ?array
{
    global $pdo;
    $id = (int)($_SESSION['user_id'] ?? 0);
    if ($id <= 0) {
        return null;
    }
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id=? AND is_active=1');
    $stmt->execute([$id]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function require_user(): array
{
    $user = current_user();
    if (!$user) {
        flash('warning', 'Сначала войдите в систему.');
        redirect_to('/login');
    }
    return $user;
}

function require_admin(): array
{
    $user = require_user();
    if (($user['role'] ?? '') !== 'admin') {
        http_response_code(403);
        exit('Требуются права администратора.');
    }
    return $user;
}

function is_admin(array $user): bool
{
    return ($user['role'] ?? '') === 'admin';
}

function uuid4(): string
{
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function json_response(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function read_json_body(int $maxBytes = 1048576): array
{
    $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > $maxBytes) {
        json_response(['detail' => 'Тело запроса слишком большое'], 413);
    }
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }
    if (strlen($raw) > $maxBytes) {
        json_response(['detail' => 'Тело запроса слишком большое'], 413);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        json_response(['detail' => 'Некорректный JSON'], 400);
    }
    return $data;
}

function app_key_raw(): string
{
    global $config;
    $key = hex2bin((string)$config['app_key']);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Некорректный app_key в config.php');
    }
    return $key;
}

function app_encrypt(string $plain, string $context = 'default'): string
{
    $key = app_key_raw();
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $context);
    if ($cipher === false) {
        throw new RuntimeException('Ошибка шифрования');
    }
    return base64_encode($iv . $tag . $cipher);
}

function app_decrypt(string $encoded, string $context = 'default'): string
{
    $raw = base64_decode($encoded, true);
    if ($raw === false || strlen($raw) < 29) {
        return '';
    }
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $cipher = substr($raw, 28);
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', app_key_raw(), OPENSSL_RAW_DATA, $iv, $tag, $context);
    return $plain === false ? '' : $plain;
}

function app_hmac(string $context, string $value): string
{
    return hash_hmac('sha256', $context . "\0" . $value, app_key_raw());
}

function client_ip(): string
{
    return trim((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

function client_ip_hash(): string
{
    return app_hmac('ip', client_ip());
}

function normalize_email(string $email): string
{
    return strtolower(trim($email));
}

function validate_password(string $password): ?string
{
    $length = strlen($password);
    if ($length < 8) {
        return 'Пароль должен содержать не менее 8 символов.';
    }
    if ($length > 128 || str_contains($password, "\0")) {
        return 'Пароль слишком длинный или содержит недопустимый символ.';
    }
    if (!preg_match('/[a-zа-яё]/iu', $password) || !preg_match('/[A-ZА-ЯЁ]/u', $password) || !preg_match('/\d/', $password)) {
        return 'Пароль должен содержать строчную, заглавную букву и цифру.';
    }
    return null;
}

function secure_password_hash(string $password): string
{
    if (defined('PASSWORD_ARGON2ID')) {
        $hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 19456,
            'time_cost' => 2,
            'threads' => 1,
        ]);
    } else {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }
    if (!is_string($hash) || $hash === '') {
        throw new RuntimeException('Не удалось создать хеш пароля.');
    }
    return $hash;
}

function secure_password_needs_rehash(string $hash): bool
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 19456,
            'time_cost' => 2,
            'threads' => 1,
        ]);
    }
    return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12]);
}

function random_secret_b64(int $bytes = 32): string
{
    return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
}

function decode_secret_b64(string $value, int $expectedBytes = 32): string
{
    $normalized = strtr(trim($value), '-_', '+/');
    $normalized .= str_repeat('=', (4 - strlen($normalized) % 4) % 4);
    $raw = base64_decode($normalized, true);
    if ($raw === false || strlen($raw) !== $expectedBytes) {
        throw new InvalidArgumentException('Некорректный секретный ключ.');
    }
    return $raw;
}

function high_entropy_token_hash(string $context, string $token): string
{
    return 'hmac$' . app_hmac($context, $token);
}

function verify_high_entropy_token(string $context, string $token, string $stored): bool
{
    if (strncmp($stored, 'hmac$', 5) === 0) {
        return hash_equals($stored, high_entropy_token_hash($context, $token));
    }
    return password_verify($token, $stored);
}

function robot_access_key(array $mission): string
{
    $encrypted = (string)($mission['robot_access_key_encrypted'] ?? '');
    $key = app_decrypt($encrypted, 'robot-access-key');
    if ($key === '' || strlen($key) !== 32) {
        throw new RuntimeException('Для робота не настроен ключ доступа.');
    }
    return $key;
}

function encrypt_for_robot(string $key, array $payload, string $aad): array
{
    if (strlen($key) !== 32) {
        throw new RuntimeException('Некорректный ключ робота.');
    }
    $nonce = random_bytes(12);
    $tag = '';
    $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    if ($cipher === false || strlen($tag) !== 16) {
        throw new RuntimeException('Не удалось зашифровать пакет для робота.');
    }
    return [
        'version' => 1,
        'algorithm' => 'A256GCM',
        'nonce' => base64_encode($nonce),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($cipher),
        'aad' => $aad,
    ];
}

function audit_log(string $action, ?string $entityType = null, ?string $entityId = null, array $details = [], ?int $userId = null): void
{
    global $pdo;
    if ($userId === null) {
        $userId = (int)($_SESSION['user_id'] ?? 0) ?: null;
    }
    try {
        $pdo->prepare('INSERT INTO audit_logs (user_id,action,entity_type,entity_id,ip_hash,details_json,created_at) VALUES (?,?,?,?,?,?,NOW())')->execute([
            $userId,
            $action,
            $entityType,
            $entityId,
            client_ip_hash(),
            json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    } catch (Throwable $e) {
        error_log('Audit log failure: ' . $e->getMessage());
    }
}

function random_pin(): string
{
    return (string)random_int(100000, 999999);
}

function normalize_rfid_uid(string $uid): string
{
    $source = strtoupper(trim($uid));
    if ($source === '' || preg_match('/[^A-F0-9:\-\s]/', $source)) {
        throw new InvalidArgumentException('UID содержит недопустимые символы. Разрешены hex, пробел, двоеточие и дефис.');
    }
    $normalized = (string)preg_replace('/[:\-\s]+/', '', $source);
    if (!preg_match('/^(?:[A-F0-9]{2}){4,16}$/', $normalized)) {
        throw new InvalidArgumentException('UID должен содержать от 4 до 16 полных байт в шестнадцатеричном виде.');
    }
    return $normalized;
}

function mask_rfid_uid(string $uid): string
{
    // В интерфейсе раскрывается только последний байт; полное значение
    // доступно лишь внутри AES-GCM зашифрованного поля.
    return '••••-' . substr($uid, -2);
}

function rfid_uid_hash(string $normalized): string
{
    return app_hmac('rfid-uid', $normalized);
}

function rfid_token(string $verifierKey, string $normalized): string
{
    return hash_hmac('sha256', $normalized, $verifierKey);
}

function status_label(string $status): string
{
    $labels = [
        'created' => 'Создан',
        'edge_accepted' => 'Принят Edge, ожидает Jetson Nano',
        'waiting_for_loading' => 'Ожидает погрузки',
        'start_requested' => 'Запуск запрошен',
        'moving_to_destination' => 'Едет к получателю',
        'arrived' => 'Прибыл',
        'waiting_auth' => 'Ожидает RFID или PIN',
        'access_granted' => 'Доступ разрешён',
        'delivered' => 'Груз выдан',
        'returning' => 'Возвращается на базу',
        'cancel_requested' => 'Отмена запрошена',
        'completed' => 'Завершён',
        'cancelled' => 'Отменён',
        'failed' => 'Ошибка',
    ];
    return $labels[$status] ?? $status;
}

function mission_status_class(string $status): string
{
    if ($status === 'completed') {
        return 'status success';
    }
    if (in_array($status, ['failed', 'cancelled'], true)) {
        return 'status danger';
    }
    if (in_array($status, ['created', 'edge_accepted', 'waiting_for_loading'], true)) {
        return 'status neutral';
    }
    return 'status progress';
}

function assigned_robot_ids(array $user): array
{
    global $pdo;
    if (is_admin($user)) {
        return array_map('intval', $pdo->query('SELECT id FROM robots')->fetchAll(PDO::FETCH_COLUMN));
    }
    $stmt = $pdo->prepare('SELECT robot_id FROM robot_assignments WHERE user_id=?');
    $stmt->execute([(int)$user['id']]);
    return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

function mission_for_user(int $id, array $user, bool $forUpdate = false): array
{
    global $pdo;
    $sql = 'SELECT m.*, r.name robot_name, r.robot_uid, r.edge_gateway_id, r.robot_access_key_encrypted, r.robot_key_version, '
        . 'p.name pickup_name, p.code pickup_code, p.marker_id pickup_marker, '
        . 'd.name destination_name, d.code destination_code, d.marker_id destination_marker, '
        . 'b.name base_name, b.code base_code, b.marker_id base_marker, '
        . 'u.full_name customer_name '
        . 'FROM missions m '
        . 'JOIN robots r ON r.id=m.robot_id '
        . 'JOIN users u ON u.id=m.customer_id '
        . 'JOIN locations p ON p.id=m.pickup_location_id '
        . 'JOIN locations d ON d.id=m.destination_location_id '
        . 'JOIN locations b ON b.id=m.base_location_id '
        . 'WHERE m.id=?';
    if ($forUpdate) {
        $sql .= ' FOR UPDATE';
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$id]);
    $mission = $stmt->fetch();
    if (!$mission) {
        http_response_code(404);
        exit('Заказ не найден.');
    }
    if (!is_admin($user) && (int)$mission['customer_id'] !== (int)$user['id']) {
        http_response_code(403);
        exit('Этот заказ создан другим оператором.');
    }
    return $mission;
}

function mission_allowed_actions(array $mission): array
{
    $actions = [];
    if ($mission['status'] === 'waiting_for_loading') {
        $actions[] = 'confirm_loaded';
    }
    if (!in_array($mission['status'], TERMINAL_MISSION_STATUSES, true) && $mission['status'] !== 'cancel_requested') {
        $actions[] = 'cancel';
    }
    return $actions;
}

function add_event(int $missionId, string $eventType, string $source, array $payload = [], ?string $eventUid = null, ?string $occurredAt = null, ?int $sequence = null): bool
{
    global $pdo;
    $eventUid = $eventUid ?: uuid4();
    $timestamp = time();
    if ($occurredAt !== null) {
        $parsed = strtotime($occurredAt);
        if ($parsed !== false && $parsed >= time() - 2592000 && $parsed <= time() + 300) {
            $timestamp = $parsed;
        }
    }
    try {
        $stmt = $pdo->prepare('INSERT INTO mission_events (event_uid,mission_id,sequence_number,event_type,source,payload_json,occurred_at) VALUES (?,?,?,?,?,?,?)');
        $stmt->execute([
            $eventUid,
            $missionId,
            $sequence,
            strtoupper($eventType),
            $source,
            json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            date('Y-m-d H:i:s', $timestamp),
        ]);
        return true;
    } catch (PDOException $e) {
        if ((string)$e->getCode() === '23000') {
            return false;
        }
        throw $e;
    }
}

function create_command(array $mission, string $type, array $payload, ?int $ttlSeconds = 86400): string
{
    global $pdo;
    $uid = uuid4();
    $expiresAt = $ttlSeconds !== null && $ttlSeconds > 0
        ? date('Y-m-d H:i:s', time() + $ttlSeconds)
        : null;
    $stmt = $pdo->prepare('INSERT INTO edge_commands (command_uid,edge_gateway_id,mission_id,command_type,payload_json,status,created_at,expires_at) VALUES (?,?,?,?,?,"pending",NOW(),?)');
    $stmt->execute([
        $uid,
        (int)$mission['edge_gateway_id'],
        (int)$mission['id'],
        $type,
        json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        $expiresAt,
    ]);
    return $uid;
}

function mission_package(array $mission): array
{
    global $pdo;
    $map = ['version'=>0,'name'=>'','layers'=>['roads'=>[],'signs'=>[],'traffic_lights'=>[]]];
    try {
        $mapRow = $pdo->query('SELECT version,name,map_json FROM facility_maps WHERE is_active=1 ORDER BY id DESC LIMIT 1')->fetch();
        if ($mapRow) {
            $decoded = json_decode((string)$mapRow['map_json'], true);
            if (is_array($decoded)) { $map['version']=(int)$mapRow['version']; $map['name']=(string)$mapRow['name']; $map['layers']=$decoded; }
        }
    } catch (Throwable $e) { error_log('Map load error: ' . $e->getMessage()); }
    $verifierKey = app_decrypt((string)($mission['rfid_verifier_key_encrypted'] ?? ''), 'mission-rfid-key');
    if ($verifierKey === '') {
        $verifierKey = random_bytes(32);
        $pdo->prepare('UPDATE missions SET rfid_verifier_key_encrypted=? WHERE id=?')->execute([
            app_encrypt($verifierKey, 'mission-rfid-key'),
            (int)$mission['id'],
        ]);
    }

    $stmt = $pdo->prepare('SELECT c.uid_encrypted FROM mission_rfid mr JOIN rfid_cards c ON c.id=mr.rfid_card_id WHERE mr.mission_id=? AND c.is_active=1 ORDER BY c.id');
    $stmt->execute([(int)$mission['id']]);
    $tokens = [];
    foreach ($stmt->fetchAll() as $card) {
        $uid = app_decrypt((string)$card['uid_encrypted'], 'rfid-card');
        if ($uid !== '') {
            $tokens[] = rfid_token($verifierKey, $uid);
        }
    }

    $accessPayload = [
        'version' => 1,
        'allowed_rfid_tokens' => array_values(array_unique($tokens)),
        'rfid_verifier_key' => base64_encode($verifierKey),
        'pin_hash' => (string)$mission['pin_hash'],
        'max_pin_attempts' => 5,
        'pin_lock_seconds' => 300,
    ];
    $aad = (string)$mission['mission_uid'] . '|' . (string)$mission['robot_uid'] . '|access-v1';
    $accessEnvelope = encrypt_for_robot(robot_access_key($mission), $accessPayload, $aad);

    return [
        'schema_version' => '2.1',
        'package_version' => 1,
        'mission_id' => $mission['mission_uid'],
        'robot_id' => $mission['robot_uid'],
        'robot_key_version' => (int)($mission['robot_key_version'] ?? 1),
        'pickup' => [
            'code' => $mission['pickup_code'],
            'name' => $mission['pickup_name'],
            'marker_id' => $mission['pickup_marker'] !== null ? (int)$mission['pickup_marker'] : null,
        ],
        'destination' => [
            'code' => $mission['destination_code'],
            'name' => $mission['destination_name'],
            'marker_id' => $mission['destination_marker'] !== null ? (int)$mission['destination_marker'] : null,
        ],
        'base' => [
            'code' => $mission['base_code'],
            'name' => $mission['base_name'],
            'marker_id' => $mission['base_marker'] !== null ? (int)$mission['base_marker'] : null,
        ],
        'cargo_description' => $mission['cargo_description'],
        'cargo_type' => (string)($mission['shipment_type'] ?? 'standard'),
        'facility_map' => $map,
        'access_envelope' => $accessEnvelope,
        'access_summary' => [
            'rfid_count' => count($tokens),
            'pin_enabled' => true,
        ],
        'return_policy' => 'wait_for_authenticated_edge_after_delivery',
        'created_at' => date(DATE_ATOM, strtotime((string)$mission['created_at'])),
    ];
}

function mission_transition_for_event(string $type): ?array
{
    $map = [
        'EDGE_ACCEPTED' => [['created'], 'edge_accepted'],
        'MISSION_STAGED' => [['created', 'edge_accepted'], 'waiting_for_loading'],
        'MISSION_STARTED' => [['start_requested'], 'moving_to_destination'],
        'ARRIVED' => [['moving_to_destination'], 'arrived'],
        'WAITING_AUTH' => [['arrived'], 'waiting_auth'],
        'ACCESS_GRANTED' => [['waiting_auth'], 'access_granted'],
        'DELIVERY_DONE' => [['access_granted'], 'delivered'],
        'RETURN_STARTED' => [['delivered'], 'returning'],
        'RETURNED_TO_BASE' => [['returning'], 'completed'],
        'MISSION_CANCELLED' => [['cancel_requested'], 'cancelled'],
        'MISSION_FAILED' => [ACTIVE_MISSION_STATUSES, 'failed'],
    ];
    return $map[$type] ?? null;
}

function process_edge_event(array $mission, array $event): bool
{
    global $pdo;
    $eventUid = trim((string)($event['event_id'] ?? ''));
    $type = strtoupper(trim((string)($event['event_type'] ?? '')));
    if ($eventUid === '' || strlen($eventUid) > 100 || $type === '' || strlen($type) > 100) {
        return false;
    }
    $existing = $pdo->prepare('SELECT id FROM mission_events WHERE event_uid=?');
    $existing->execute([$eventUid]);
    if ($existing->fetchColumn()) {
        return true;
    }

    $source = strtolower((string)($event['source'] ?? 'edge'));
    if (!in_array($source, ['edge', 'robot'], true)) {
        return false;
    }
    $payload = is_array($event['payload'] ?? null) ? $event['payload'] : [];
    $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($payloadJson === false || strlen($payloadJson) > 65536) {
        return false;
    }
    $sequence = isset($event['sequence_number']) && $event['sequence_number'] !== null
        ? (int)$event['sequence_number']
        : null;

    if ($type === 'COMMAND_ACK') {
        $commandId = trim((string)($payload['command_id'] ?? ''));
        $commandType = trim((string)($payload['command_type'] ?? ''));
        $accepted = !array_key_exists('accepted', $payload) || (bool)$payload['accepted'];
        if ($commandId === '' || $commandType === '') {
            return false;
        }
        $stmt = $pdo->prepare('SELECT status,command_type FROM edge_commands WHERE command_uid=? AND edge_gateway_id=? AND mission_id=? FOR UPDATE');
        $stmt->execute([$commandId, (int)$mission['edge_gateway_id'], (int)$mission['id']]);
        $command = $stmt->fetch();
        if (!$command || !hash_equals((string)$command['command_type'], $commandType)) {
            return false;
        }
        $commandStatus = $accepted ? 'acked' : 'rejected';
        if ((string)$command['status'] === 'pending') {
            $pdo->prepare('UPDATE edge_commands SET status=?,acked_at=NOW() WHERE command_uid=?')->execute([$commandStatus, $commandId]);
        } elseif ((string)$command['status'] !== $commandStatus) {
            return false;
        }
        if (!$accepted && in_array($commandType, ['stage_mission', 'start_mission'], true) && !in_array((string)$mission['status'], TERMINAL_MISSION_STATUSES, true)) {
            $pdo->prepare('UPDATE missions SET status="failed",version=version+1 WHERE id=?')->execute([(int)$mission['id']]);
            $pdo->prepare('UPDATE robots SET status="idle" WHERE id=?')->execute([(int)$mission['robot_id']]);
        }
        add_event((int)$mission['id'], $type, $source, $payload, $eventUid, $event['occurred_at'] ?? null, null);
        return true;
    }

    $transition = mission_transition_for_event($type);
    if ($transition === null || $sequence === null || $sequence < 1) {
        return false;
    }

    $last = (int)$mission['last_event_sequence'];
    // Неизвестное событие со старым номером не считается успешным повтором:
    // настоящий повтор уже был бы найден выше по event_uid.
    if ($sequence <= $last || $sequence !== $last + 1) {
        return false;
    }

    [$allowedFrom, $target] = $transition;
    $current = (string)$mission['status'];
    if (in_array($current, TERMINAL_MISSION_STATUSES, true) || !in_array($current, $allowedFrom, true)) {
        return false;
    }

    $inserted = add_event((int)$mission['id'], $type, $source, $payload, $eventUid, $event['occurred_at'] ?? null, $sequence);
    if (!$inserted) {
        return false;
    }
    $sql = 'UPDATE missions SET status=?,version=version+1,last_event_sequence=?';
    $params = [$target, $sequence];
    if ($target === 'completed') {
        $sql .= ',completed_at=NOW()';
    }
    $sql .= ' WHERE id=?';
    $params[] = (int)$mission['id'];
    $pdo->prepare($sql)->execute($params);

    if ($type === 'RETURNED_TO_BASE') {
        $pdo->prepare('UPDATE robots SET status="idle",current_location_id=? WHERE id=?')->execute([(int)$mission['base_location_id'], (int)$mission['robot_id']]);
    } elseif ($type === 'ARRIVED') {
        $pdo->prepare('UPDATE robots SET current_location_id=? WHERE id=?')->execute([(int)$mission['destination_location_id'], (int)$mission['robot_id']]);
    } elseif ($type === 'MISSION_FAILED' || $type === 'MISSION_CANCELLED') {
        $pdo->prepare('UPDATE robots SET status="idle" WHERE id=?')->execute([(int)$mission['robot_id']]);
    } else {
        $pdo->prepare('UPDATE robots SET status="busy" WHERE id=?')->execute([(int)$mission['robot_id']]);
    }
    return true;
}

function format_dt(?string $value): string
{
    if (!$value) {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? '—' : date('d.m.Y H:i:s', $ts);
}

function bearer_token(): string
{
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if ($auth === '' && function_exists('getallheaders')) {
        $headers = getallheaders();
        $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    }
    if (preg_match('/^Bearer\s+(.+)$/i', trim((string)$auth), $match)) {
        return trim($match[1]);
    }
    return trim((string)($_SERVER['HTTP_X_EDGE_TOKEN'] ?? ''));
}

function event_label(string $type): string
{
    $labels = [
        'ORDER_CREATED' => 'Заказ создан',
        'EDGE_ACCEPTED' => 'Edge принял пакет заказа',
        'MISSION_STAGED' => 'Jetson Nano сохранил автономный пакет',
        'LOADING_CONFIRMED' => 'Погрузка подтверждена оператором',
        'MISSION_STARTED' => 'Робот начал движение',
        'ARRIVED' => 'Робот прибыл в точку',
        'WAITING_AUTH' => 'Ожидание RFID или PIN',
        'ACCESS_GRANTED' => 'Доступ к грузу разрешён',
        'DELIVERY_DONE' => 'Груз выдан',
        'RETURN_STARTED' => 'Робот начал возврат на базу',
        'RETURNED_TO_BASE' => 'Робот вернулся на базу',
        'MISSION_FAILED' => 'Ошибка выполнения',
        'MISSION_CANCELLED' => 'Робот подтвердил отмену',
        'COMMAND_ACK' => 'Команда подтверждена',
        'CANCEL_REQUESTED' => 'Оператор запросил отмену',
        'COMMAND_EXPIRED' => 'Команда просрочена',
    ];
    return $labels[$type] ?? $type;
}

function page_revision(array $user, string $scope): string
{
    global $pdo;
    if ($scope === 'dashboard') {
        if (is_admin($user)) {
            $missionValue = $pdo->query('SELECT CONCAT(COALESCE(MAX(updated_at),""),"|",COUNT(*)) FROM missions')->fetchColumn();
            $robotValue = $pdo->query('SELECT CONCAT(COALESCE(MAX(updated_at),""),"|",COALESCE(MAX(last_robot_seen_at),""),"|",COUNT(*)) FROM robots')->fetchColumn();
            $edgeValue = $pdo->query('SELECT CONCAT(COALESCE(MAX(last_seen_at),""),"|",COUNT(*)) FROM edge_gateways')->fetchColumn();
        } else {
            $stmt = $pdo->prepare('SELECT CONCAT(COALESCE(MAX(updated_at),""),"|",COUNT(*)) FROM missions WHERE customer_id=?');
            $stmt->execute([(int)$user['id']]);
            $missionValue = $stmt->fetchColumn();
            $stmt = $pdo->prepare('SELECT CONCAT(COALESCE(MAX(r.updated_at),""),"|",COALESCE(MAX(r.last_robot_seen_at),""),"|",COUNT(*),"|",COALESCE(MAX(e.last_seen_at),"")) FROM robots r JOIN robot_assignments ra ON ra.robot_id=r.id JOIN edge_gateways e ON e.id=r.edge_gateway_id WHERE ra.user_id=?');
            $stmt->execute([(int)$user['id']]);
            $robotValue = $stmt->fetchColumn();
            $edgeValue = '';
        }
        return hash('sha256', (string)$missionValue . '|' . (string)$robotValue . '|' . (string)$edgeValue);
    }
    if ($scope === 'requests' && is_admin($user)) {
        return hash('sha256', (string)$pdo->query('SELECT CONCAT(COALESCE(MAX(COALESCE(reviewed_at,created_at)),""),"|",COUNT(*)) FROM access_requests')->fetchColumn());
    }
    if ($scope === 'users' && is_admin($user)) {
        $users = $pdo->query('SELECT CONCAT(COALESCE(MAX(updated_at),""),"|",COUNT(*)) FROM users')->fetchColumn();
        $assignments = $pdo->query('SELECT COALESCE(GROUP_CONCAT(CONCAT(user_id,":",robot_id) ORDER BY user_id,robot_id SEPARATOR "|"),"") FROM robot_assignments')->fetchColumn();
        return hash('sha256', (string)$users . '|' . (string)$assignments);
    }
    if ($scope === 'recipients') {
        return hash('sha256', (string)$pdo->query('SELECT CONCAT((SELECT COALESCE(MAX(updated_at),"") FROM recipients),"|",(SELECT COALESCE(MAX(updated_at),"") FROM rfid_cards))')->fetchColumn());
    }
    return hash('sha256', date('Y-m-d H:i'));
}
