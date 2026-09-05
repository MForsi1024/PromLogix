<?php
declare(strict_types=1);

require __DIR__ . '/inc/bootstrap.php';

$path = request_path();
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

/**
 * Secure 0.5.x requires the database migration.  Older databases can load
 * config.php successfully but then fail with HTTP 500 on the first query to a
 * new column.  Detect that state early and show a controlled maintenance page.
 */
function secure_schema_missing(PDO $pdo): array
{
    $requiredColumns = [
        ['users', 'last_login_at'],
        ['users', 'password_changed_at'],
        ['access_requests', 'password_hash'],
        ['robots', 'telemetry_status'],
        ['robots', 'robot_access_key_encrypted'],
        ['rfid_cards', 'uid_hash'],
        ['rfid_cards', 'uid_encrypted'],
        ['missions', 'version'],
        ['missions', 'last_event_sequence'],
        ['missions', 'rfid_verifier_key_encrypted'],
        ['missions', 'shipment_type'],
        ['missions', 'sender_name'],
        ['missions', 'recipient_name'],
        ['mission_events', 'sequence_number'],
        ['edge_commands', 'expires_at'],
    ];
    $missing = [];
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM information_schema.COLUMNS '
        . 'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?'
    );
    foreach ($requiredColumns as [$table, $column]) {
        $stmt->execute([$table, $column]);
        if ((int)$stmt->fetchColumn() === 0) {
            $missing[] = $table . '.' . $column;
        }
    }
    $tableStmt = $pdo->prepare(
        'SELECT COUNT(*) FROM information_schema.TABLES '
        . 'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?'
    );
    foreach (['audit_logs', 'schema_migrations', 'facility_maps'] as $table) {
        $tableStmt->execute([$table]);
        if ((int)$tableStmt->fetchColumn() === 0) {
            $missing[] = $table;
        }
    }
    return $missing;
}

$schemaMissing = secure_schema_missing($pdo);
$maintenanceAllowedPaths = ['/health', '/login', '/logout', '/migrate-client-model'];
if ($schemaMissing && !in_array($path, $maintenanceAllowedPaths, true)) {
    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>Требуется восстановление базы</title>'
        . '<style>body{font-family:system-ui,sans-serif;background:#f3f6fb;color:#172033;padding:32px}'
        . '.box{max-width:760px;margin:40px auto;background:white;border:1px solid #d8e0ec;border-radius:16px;padding:28px}'
        . 'code{background:#eef2f7;padding:2px 6px;border-radius:6px}</style></head><body><div class="box">'
        . '<h1>Требуется обновление структуры базы</h1>'
        . '<p>Код Secure 0.5.x установлен, но миграция MySQL не завершена. '
        . 'Поэтому вход временно остановлен вместо HTTP 500.</p>'
        . '<p>Запустите одноразовый файл восстановления из комплекта <code>v0.5.4</code>, '
        . 'а затем удалите его с хостинга.</p>'
        . '<p><small>Не хватает: ' . h(implode(', ', $schemaMissing)) . '</small></p>'
        . '</div></body></html>';
    exit;
}

if ($path === '/migrate-client-model') {
    require __DIR__ . '/migrate-client-model.php';
    exit;
}

if ($path === '/health' && $method === 'GET') {
    json_response(['status' => $schemaMissing ? 'degraded' : 'ok', 'service' => 'cloud-php', 'version' => '0.5.4', 'schema_ready' => !$schemaMissing, 'time' => date(DATE_ATOM)]);
}

if ($path === '/api/edge/sync' && $method === 'POST') {
    $payload = read_json_body(2097152);
    $token = bearer_token();
    $edgeId = trim((string)($payload['edge_id'] ?? ''));
    if ($token === '' || $edgeId === '') {
        json_response(['detail' => 'Требуются Edge ID и токен'], 401);
    }
    $stmt = $pdo->prepare('SELECT * FROM edge_gateways WHERE edge_id=?');
    $stmt->execute([$edgeId]);
    $edge = $stmt->fetch();
    if (!$edge || !verify_high_entropy_token('edge-token:' . $edgeId, $token, (string)$edge['token_hash'])) {
        usleep(random_int(100000, 300000));
        json_response(['detail' => 'Неверный Edge ID или токен'], 403);
    }
    if (strncmp((string)$edge['token_hash'], 'hmac$', 5) !== 0) {
        $pdo->prepare('UPDATE edge_gateways SET token_hash=? WHERE id=?')->execute([
            high_entropy_token_hash('edge-token:' . $edgeId, $token),
            (int)$edge['id'],
        ]);
        $edge['token_hash'] = high_entropy_token_hash('edge-token:' . $edgeId, $token);
    }

    $pdo->beginTransaction();
    try {
        $pdo->prepare('UPDATE edge_gateways SET last_seen_at=NOW() WHERE id=?')->execute([(int)$edge['id']]);

        $expiredStmt = $pdo->prepare('SELECT c.id,c.command_type,c.mission_id,m.status mission_status,m.robot_id FROM edge_commands c LEFT JOIN missions m ON m.id=c.mission_id WHERE c.edge_gateway_id=? AND c.status="pending" AND c.expires_at IS NOT NULL AND c.expires_at<NOW() FOR UPDATE');
        $expiredStmt->execute([(int)$edge['id']]);
        foreach ($expiredStmt->fetchAll() as $expired) {
            $pdo->prepare('UPDATE edge_commands SET status="expired" WHERE id=?')->execute([(int)$expired['id']]);
            if ($expired['mission_id'] !== null && in_array((string)$expired['command_type'], ['stage_mission', 'start_mission'], true) && !in_array((string)$expired['mission_status'], TERMINAL_MISSION_STATUSES, true)) {
                $pdo->prepare('UPDATE missions SET status="failed",version=version+1 WHERE id=?')->execute([(int)$expired['mission_id']]);
                $pdo->prepare('UPDATE robots SET status="idle" WHERE id=?')->execute([(int)$expired['robot_id']]);
                add_event((int)$expired['mission_id'], 'COMMAND_EXPIRED', 'cloud', ['command_type' => (string)$expired['command_type']]);
            }
        }

        foreach (($payload['robot_heartbeats'] ?? []) as $heartbeat) {
            if (!is_array($heartbeat)) {
                continue;
            }
            $robotUid = trim((string)($heartbeat['robot_id'] ?? ''));
            if ($robotUid === '') {
                continue;
            }
            $battery = isset($heartbeat['battery_percent']) ? max(0, min(100, (int)$heartbeat['battery_percent'])) : null;
            $status = substr(trim((string)($heartbeat['status'] ?? 'online')), 0, 50);
            $stmt = $pdo->prepare('UPDATE robots SET last_robot_seen_at=NOW(),battery_percent=COALESCE(?,battery_percent),telemetry_status=? WHERE robot_uid=? AND edge_gateway_id=?');
            $stmt->execute([$battery, $status, $robotUid, (int)$edge['id']]);
        }

        // Edge отправляет outbox в фактическом порядке создания. Сохраняем его:
        // EDGE_ACCEPTED должен идти до последовательных событий Jetson Nano.
        $events = is_array($payload['events'] ?? null) ? $payload['events'] : [];
        $acked = [];
        foreach ($events as $event) {
            if (!is_array($event)) {
                continue;
            }
            $missionUid = trim((string)($event['mission_id'] ?? ''));
            $eventUid = trim((string)($event['event_id'] ?? ''));
            if ($missionUid === '' || $eventUid === '') {
                continue;
            }
            $stmt = $pdo->prepare('SELECT m.*,r.edge_gateway_id FROM missions m JOIN robots r ON r.id=m.robot_id WHERE m.mission_uid=? AND r.edge_gateway_id=? FOR UPDATE');
            $stmt->execute([$missionUid, (int)$edge['id']]);
            $mission = $stmt->fetch();
            if (!$mission) {
                continue;
            }
            if (process_edge_event($mission, $event)) {
                $acked[] = $eventUid;
            }
        }

        $stmt = $pdo->prepare('SELECT c.*,m.mission_uid FROM edge_commands c LEFT JOIN missions m ON m.id=c.mission_id WHERE c.edge_gateway_id=? AND c.status="pending" AND (c.expires_at IS NULL OR c.expires_at>=NOW()) ORDER BY c.id LIMIT 50');
        $stmt->execute([(int)$edge['id']]);
        $commands = [];
        foreach ($stmt->fetchAll() as $command) {
            $commands[] = [
                'command_id' => $command['command_uid'],
                'type' => $command['command_type'],
                'mission_id' => $command['mission_uid'],
                'created_at' => date(DATE_ATOM, strtotime((string)$command['created_at'])),
                'expires_at' => $command['expires_at'] ? date(DATE_ATOM, strtotime((string)$command['expires_at'])) : null,
                'payload' => json_decode((string)$command['payload_json'], true) ?: [],
            ];
        }
        $pdo->commit();
        json_response([
            'schema_version' => '2.1',
            'server_time' => date(DATE_ATOM),
            'acked_event_ids' => array_values(array_unique($acked)),
            'commands' => $commands,
        ]);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Edge sync error: ' . $e->getMessage());
        json_response(['detail' => 'Ошибка синхронизации'], 500);
    }
}

if ($method === 'GET' && preg_match('#^/api/missions/(\d+)$#', $path, $match)) {
    $user = require_user();
    $mission = mission_for_user((int)$match[1], $user);
    $stmt = $pdo->prepare('SELECT event_type,source,occurred_at FROM mission_events WHERE mission_id=? ORDER BY occurred_at DESC,id DESC LIMIT 30');
    $stmt->execute([(int)$mission['id']]);
    $events = array_map(static function (array $event): array {
        return [
            'type' => $event['event_type'],
            'label' => event_label((string)$event['event_type']),
            'source' => $event['source'],
            'occurred_at' => format_dt((string)$event['occurred_at']),
        ];
    }, $stmt->fetchAll());
    json_response([
        'id' => (int)$mission['id'],
        'mission_id' => $mission['mission_uid'],
        'status' => $mission['status'],
        'status_label' => status_label((string)$mission['status']),
        'status_class' => mission_status_class((string)$mission['status']),
        'version' => (int)$mission['version'],
        'allowed_actions' => mission_allowed_actions($mission),
        'updated_at' => format_dt((string)$mission['updated_at']),
        'events' => $events,
    ]);
}

if ($path === '/api/revision' && $method === 'GET') {
    $user = require_user();
    $scope = trim((string)($_GET['scope'] ?? 'dashboard'));
    json_response(['scope' => $scope, 'revision' => page_revision($user, $scope)]);
}

if ($path === '/' && $method === 'GET') {
    redirect_to(current_user() ? '/dashboard' : '/login');
}

if ($path === '/login' && $method === 'GET') {
    if (current_user()) {
        redirect_to('/dashboard');
    }
    render_header('Вход');
    ?>
    <section class="card auth-card">
        <div class="brand-row"><img class="brand-logo brand-logo-large" src="<?= h(base_url('/assets/promlogix.jpg')) ?>" alt=""><div><h1>PromLogix</h1><p>Автономная доставка грузов</p></div></div>
        <form method="post" action="<?= h(base_url('/login')) ?>" class="form-stack">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <label>Email<input type="email" name="email" autocomplete="username" maxlength="190" required></label>
            <label>Пароль<input type="password" name="password" autocomplete="current-password" required></label>
            <button class="button primary" type="submit">Войти</button>
        </form>
        <p class="muted">Нет аккаунта? <a href="<?= h(base_url('/request-access')) ?>">Зарегистрироваться</a></p>
    </section>
    <?php render_footer(); exit;
}

if ($path === '/login' && $method === 'POST') {
    verify_csrf();
    $email = normalize_email((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    if (strlen($email) > 190 || strlen($password) > 128 || str_contains($password, "\0")) {
        usleep(random_int(100000, 300000));
        flash('danger', 'Неверный email или пароль.');
        redirect_to('/login');
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE email=? AND is_active=1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    $passwordValid = $user && password_verify($password, (string)$user['password_hash']);

    if (!$passwordValid) {
        // Жёсткая блокировка входа отключена. Оставляем одинаковый ответ и
        // небольшую случайную задержку, чтобы не раскрывать существование аккаунта.
        audit_log('login_failed', 'user_email_hash', app_hmac('audit-email', $email), [
            'blocked' => false,
            'lockout_disabled' => true,
        ]);
        usleep(random_int(200000, 450000));
        flash('danger', 'Неверный email или пароль.');
        redirect_to('/login');
    }

    if (secure_password_needs_rehash((string)$user['password_hash'])) {
        $pdo->prepare('UPDATE users SET password_hash=?,password_changed_at=NOW() WHERE id=?')->execute([
            secure_password_hash($password),
            (int)$user['id'],
        ]);
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['csrf'] = bin2hex(random_bytes(24));
    $pdo->prepare('UPDATE users SET last_login_at=NOW() WHERE id=?')->execute([(int)$user['id']]);
    audit_log('login_success', 'user', (string)$user['id'], [], (int)$user['id']);
    redirect_to('/dashboard');
}

if ($path === '/logout' && $method === 'POST') {
    verify_csrf();
    audit_log('logout');
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'] ?? '',
            'secure' => (bool)$params['secure'],
            'httponly' => (bool)$params['httponly'],
            'samesite' => 'Lax',
        ]);
    }
    session_destroy();
    redirect_to('/login');
}

if ($path === '/request-access' && $method === 'GET') {
    render_header('Заявка на доступ');
    ?>
    <section class="card auth-card">
        <div class="brand-row"><img class="brand-logo brand-logo-large" src="<?= h(base_url('/assets/promlogix.jpg')) ?>" alt=""><div><h1>Регистрация в PromLogix</h1><p>Вход станет доступен после подтверждения администратора.</p></div></div>
        <form method="post" action="<?= h(base_url('/request-access')) ?>" class="form-stack">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <label>ФИО<input name="full_name" maxlength="255" required></label>
            <label>Email<input type="email" name="email" maxlength="190" required></label>
            <label>Телефон<input name="organization" maxlength="255" placeholder="+7 ..." required></label>
            <label>Комментарий<textarea name="reason" maxlength="3000" placeholder="Дополнительная информация" required></textarea></label>
            <label>Пароль<input type="password" name="password" minlength="8" maxlength="128" autocomplete="new-password" required aria-describedby="password-rules"></label>
            <div id="password-rules" class="password-rules" data-password-rules><span data-rule="length">Не менее 8 символов</span><span data-rule="lower">Строчная буква</span><span data-rule="upper">Заглавная буква</span><span data-rule="digit">Цифра</span></div>
            <label>Повторите пароль<input type="password" name="password_repeat" minlength="8" maxlength="128" autocomplete="new-password" required></label>
            <p class="password-match" data-password-match>Пароли должны совпадать.</p>
            <button class="button primary" type="submit" data-registration-submit disabled>Отправить заявку</button>
        </form>
        <p class="muted"><a href="<?= h(base_url('/login')) ?>">Вернуться ко входу</a></p>
    </section>
    <?php render_footer(); exit;
}

if ($path === '/request-access' && $method === 'POST') {
    verify_csrf();
    $fullName = trim((string)($_POST['full_name'] ?? ''));
    $email = normalize_email((string)($_POST['email'] ?? ''));
    $organization = trim((string)($_POST['organization'] ?? ''));
    $reason = trim((string)($_POST['reason'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $repeat = (string)($_POST['password_repeat'] ?? '');
    $passwordError = validate_password($password);
    if ($fullName === '' || strlen($fullName) > 255 || !filter_var($email, FILTER_VALIDATE_EMAIL) || $organization === '' || $reason === '' || $passwordError !== null || !hash_equals($password, $repeat)) {
        flash('danger', $passwordError ?: 'Проверьте заполнение формы и совпадение паролей.');
        redirect_to('/request-access');
    }
    $stmt = $pdo->prepare('SELECT id,is_active FROM users WHERE email=?');
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        flash('warning', 'Аккаунт с таким email уже существует. Обратитесь к администратору.');
        redirect_to('/request-access');
    }
    $stmt = $pdo->prepare('SELECT id FROM access_requests WHERE email=? AND status="pending"');
    $stmt->execute([$email]);
    if ($stmt->fetchColumn()) {
        flash('warning', 'Заявка с этим email уже ожидает рассмотрения.');
        redirect_to('/request-access');
    }
    $pdo->prepare('INSERT INTO access_requests (full_name,email,organization,reason,password_hash,status,submit_ip_hash,created_at) VALUES (?,?,?,?,?,"pending",?,NOW())')->execute([
        $fullName, $email, $organization, $reason, secure_password_hash($password), client_ip_hash()
    ]);
    audit_log('access_request_created', 'access_request', (string)$pdo->lastInsertId());
    flash('success', 'Заявка отправлена. После одобрения можно будет сразу войти с указанным паролем.');
    redirect_to('/request-access');
}

if (preg_match('#^/activate/#', $path)) {
    http_response_code(410);
    exit('Активация по ссылке отключена. Пароль теперь задаётся при подаче заявки.');
}

if ($path === '/dashboard' && $method === 'GET') {
    $user = require_user();
    $robotIds = is_admin($user) ? assigned_robot_ids($user) : [];
    $robots = [];
    $missions = [];
    if ($robotIds) {
        $placeholders = implode(',', array_fill(0, count($robotIds), '?'));
        $stmt = $pdo->prepare("SELECT r.*,l.name current_location,e.name edge_name,e.last_seen_at,IF(e.last_seen_at IS NOT NULL AND TIMESTAMPDIFF(SECOND,e.last_seen_at,NOW())<40,1,0) edge_online,IF(r.last_robot_seen_at IS NOT NULL AND TIMESTAMPDIFF(SECOND,r.last_robot_seen_at,NOW())<20,1,0) robot_online FROM robots r LEFT JOIN locations l ON l.id=r.current_location_id JOIN edge_gateways e ON e.id=r.edge_gateway_id WHERE r.id IN ($placeholders) ORDER BY r.name");
        $stmt->execute($robotIds);
        $robots = $stmt->fetchAll();
    }
    if (is_admin($user)) {
        $stmt = $pdo->query('SELECT m.*,r.name robot_name,p.name pickup_name,d.name destination_name FROM missions m JOIN robots r ON r.id=m.robot_id JOIN locations p ON p.id=m.pickup_location_id JOIN locations d ON d.id=m.destination_location_id ORDER BY m.created_at DESC LIMIT 100');
    } else {
        $stmt = $pdo->prepare('SELECT m.*,r.name robot_name,p.name pickup_name,d.name destination_name FROM missions m JOIN robots r ON r.id=m.robot_id JOIN locations p ON p.id=m.pickup_location_id JOIN locations d ON d.id=m.destination_location_id WHERE m.customer_id=? ORDER BY m.created_at DESC LIMIT 100');
        $stmt->execute([(int)$user['id']]);
    }
    $missions = $stmt->fetchAll();
    if (is_admin($user)) {
        $counts = $pdo->query('SELECT SUM(status NOT IN ("completed","cancelled","failed")) active_count,SUM(status="completed") completed_count FROM missions')->fetch();
    } else {
        $countStmt = $pdo->prepare('SELECT SUM(status NOT IN ("completed","cancelled","failed")) active_count,SUM(status="completed") completed_count FROM missions WHERE customer_id=?');
        $countStmt->execute([(int)$user['id']]);
        $counts = $countStmt->fetch();
    }
    $activeCount = (int)($counts['active_count'] ?? 0);
    $completedCount = (int)($counts['completed_count'] ?? 0);
    render_header(is_admin($user) ? 'Панель администратора' : 'Мои заказы', $user, 'dashboard');
    page_title('Мои заказы', 'История и состояние доставок', '<a class="button primary" href="' . h(base_url('/missions/new')) . '">Создать заказ</a>');
    ?>
    <div data-revision-scope="dashboard" data-revision="<?= h(page_revision($user, 'dashboard')) ?>"></div>
    <section class="grid <?= is_admin($user)?'cols-3':'cols-2' ?>">
        <?php if (is_admin($user)): ?><div class="card metric"><span>Роботов</span><strong><?= count($robots) ?></strong></div><?php endif; ?>
        <div class="card metric"><span>Активных заказов</span><strong><?= $activeCount ?></strong></div>
        <div class="card metric"><span>Завершено</span><strong><?= $completedCount ?></strong></div>
    </section>
    <?php if (is_admin($user)): ?><section class="section"><div class="section-title"><h2>Роботы</h2></div>
        <?php if (!$robots): empty_state('Роботов нет', 'Добавьте робота и подключите его через Edge.'); else: ?>
        <div class="grid cols-2"><?php foreach ($robots as $robot): ?><article class="card card-pad">
            <div class="item-card-head"><div><h3><?= h($robot['name']) ?></h3><p class="mono"><?= h($robot['robot_uid']) ?></p></div><div><span class="<?= $robot['edge_online'] ? 'status success' : 'status danger' ?>"><?= $robot['edge_online'] ? 'Edge на связи' : 'Edge не отвечает' ?></span> <span class="<?= $robot['robot_online'] ? 'status success' : 'status danger' ?>"><?= $robot['robot_online'] ? 'Orange Pi на связи' : 'Orange Pi не отвечает' ?></span></div></div>
            <div class="detail-list section"><div><span>Режим</span><strong><?= h($robot['status']) ?></strong></div><div><span>Телеметрия</span><strong><?= h($robot['telemetry_status']) ?></strong></div><div><span>Заряд</span><strong><?= $robot['battery_percent'] !== null ? (int)$robot['battery_percent'] . '%' : '—' ?></strong></div><div><span>Точка</span><strong><?= h($robot['current_location'] ?: 'Не определена') ?></strong></div><div><span>Связь робота</span><strong><?= h(format_dt($robot['last_robot_seen_at'])) ?></strong></div></div>
        </article><?php endforeach; ?></div><?php endif; ?>
    </section><?php endif; ?>
    <section class="section"><div class="section-title"><h2>Последние заказы</h2></div>
        <?php if (!$missions): empty_state('Заказов пока нет', 'Создайте первый заказ.'); else: ?><div class="table-wrap"><table><thead><tr><th>Заказ</th><th>Робот</th><th>Маршрут</th><th>Статус</th><th>Создан</th></tr></thead><tbody>
        <?php foreach ($missions as $mission): ?><tr><td><a href="<?= h(base_url('/missions/' . $mission['id'])) ?>"><strong><?= h(substr($mission['mission_uid'], 0, 8)) ?></strong></a></td><td><?= h($mission['robot_name']) ?></td><td><?= h($mission['pickup_name']) ?> → <?= h($mission['destination_name']) ?></td><td><span class="<?= h(mission_status_class((string)$mission['status'])) ?>"><?= h(status_label((string)$mission['status'])) ?></span></td><td><?= h(format_dt($mission['created_at'])) ?></td></tr><?php endforeach; ?>
        </tbody></table></div><?php endif; ?>
    </section>
    <?php render_footer(); exit;
}

if ($path === '/missions/new' && $method === 'GET') {
    $user = require_user();
    $locations = $pdo->query('SELECT * FROM locations ORDER BY kind="base" DESC,name')->fetchAll();
    $cards = $pdo->query('SELECT c.id,c.label,c.uid_mask,r.full_name recipient_name,r.department FROM rfid_cards c JOIN recipients r ON r.id=c.recipient_id WHERE c.is_active=1 ORDER BY r.full_name,c.label')->fetchAll();
    render_header('Новый заказ', $user, 'new');
    page_title('Новый заказ');
    ?>
    <section class="card card-pad"><form method="post" action="<?= h(base_url('/missions/new')) ?>" class="form-grid">
        <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
        <fieldset class="wide cargo-section"><label class="cargo-section-toggle"><input type="checkbox" name="cargo_modes[]" value="standard" checked><span><strong>Габаритный груз</strong><small>Включить габаритную часть заказа</small></span></label><div class="cargo-section-fields" data-standard-fields><label>Описание габаритного груза<textarea name="standard_description" maxlength="1000" required></textarea></label><fieldset data-standard-only><legend>Получатели для RFID</legend><div class="check-list"><?php if (!$cards): ?><p class="muted">RFID-карт нет — будет доступен PIN.</p><?php endif; ?><?php foreach ($cards as $card): ?><label class="check-row"><input type="checkbox" name="rfid_ids[]" value="<?= (int)$card['id'] ?>"><span><strong><?= h($card['recipient_name']) ?></strong> · <?= h($card['label']) ?> · <span class="mono"><?= h($card['uid_mask']) ?></span></span></label><?php endforeach; ?></div></fieldset></div></fieldset>
        <fieldset class="wide cargo-section"><label class="cargo-section-toggle"><input type="checkbox" name="cargo_modes[]" value="oversized"><span><strong>Негабаритный груз</strong><small>Включить негабаритную часть заказа</small></span></label><div class="cargo-section-fields" data-oversized-fields hidden><label>Описание негабаритного груза<textarea name="oversized_description" maxlength="1000" disabled></textarea></label></div></fieldset>
        <label>Отправитель<input name="sender_name" maxlength="255" required></label>
        <label>Получатель<input name="recipient_name" maxlength="255" required></label>
        <label>Точка погрузки<select name="pickup_location_id" required><option value="">Выберите</option><?php foreach ($locations as $location): ?><option value="<?= (int)$location['id'] ?>"><?= h($location['name']) ?> · маркер <?= h((string)$location['marker_id']) ?></option><?php endforeach; ?></select></label>
        <label>Точка доставки<select name="destination_location_id" required><option value="">Выберите</option><?php foreach ($locations as $location): ?><option value="<?= (int)$location['id'] ?>"><?= h($location['name']) ?> · маркер <?= h((string)$location['marker_id']) ?></option><?php endforeach; ?></select></label>
        <section class="route-map wide" data-route-map><div class="route-map-head"><strong>Схема маршрута</strong><span>Точки из карты объекта</span></div><div class="route-map-canvas"><?php foreach ($locations as $location): ?><button type="button" class="map-location" data-location-id="<?= (int)$location['id'] ?>" style="--map-x:<?= max(0,min(100,(float)$location['x'])) ?>%;--map-y:<?= max(0,min(100,(float)$location['y'])) ?>%" title="<?= h($location['name']) ?>"><span></span><small><?= h($location['name']) ?></small></button><?php endforeach; ?></div><div class="map-legend"><span><i class="pickup"></i>Отправление</span><span><i class="destination"></i>Назначение</span></div></section>
        <button class="button primary wide" type="submit">Найти робота и создать заказ</button>
    </form></section>
    <?php render_footer(); exit;
}

if ($path === '/missions/new' && $method === 'POST') {
    verify_csrf();
    $user = require_user();
    $cargoModes = array_values(array_intersect(['standard', 'oversized'], array_map('strval', (array)($_POST['cargo_modes'] ?? []))));
    $shipmentType = count($cargoModes) === 2 ? 'mixed' : ($cargoModes[0] ?? '');
    $senderName = trim((string)($_POST['sender_name'] ?? ''));
    $recipientName = trim((string)($_POST['recipient_name'] ?? ''));
    $pickupId = (int)($_POST['pickup_location_id'] ?? 0);
    $destinationId = (int)($_POST['destination_location_id'] ?? 0);
    $standardDescription = trim((string)($_POST['standard_description'] ?? ''));
    $oversizedDescription = trim((string)($_POST['oversized_description'] ?? ''));
    $cargoParts = [];
    if (in_array('standard', $cargoModes, true)) $cargoParts[] = 'Габарит: ' . $standardDescription;
    if (in_array('oversized', $cargoModes, true)) $cargoParts[] = 'Негабарит: ' . $oversizedDescription;
    $cargo = implode("\n", $cargoParts);
    $rfidIds = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['rfid_ids'] ?? [])))));
    if (!in_array($shipmentType, ['standard', 'oversized', 'mixed'], true) || (in_array('standard',$cargoModes,true) && $standardDescription==='') || (in_array('oversized',$cargoModes,true) && $oversizedDescription==='') || $senderName === '' || $recipientName === '' || strlen($senderName) > 255 || strlen($recipientName) > 255 || $pickupId <= 0 || $destinationId <= 0 || $pickupId === $destinationId || $cargo === '' || strlen($cargo) > 2100) {
        flash('danger', 'Проверьте робота, точки и описание груза.');
        redirect_to('/missions/new');
    }
    $pin = random_pin();
    $pdo->beginTransaction();
    try {
        // Пока карта роботов не содержит координат/графа, выбираем робота
        // в точке отправления, затем любого свободного по ID.
        $stmt = $pdo->prepare('SELECT r.* FROM robots r WHERE r.status="idle" AND NOT EXISTS (SELECT 1 FROM missions m WHERE m.robot_id=r.id AND m.status NOT IN ("completed","cancelled","failed")) ORDER BY (r.current_location_id=?) DESC, r.id LIMIT 1 FOR UPDATE');
        $stmt->execute([$pickupId]);
        $robot = $stmt->fetch();
        if (!$robot) {
            throw new RuntimeException('Робот уже занят другим заказом.');
        }
        $robotId = (int)$robot['id'];
        $place = $pdo->prepare('SELECT id FROM locations WHERE id IN (?,?)');
        $place->execute([$pickupId, $destinationId]);
        if (count($place->fetchAll()) !== 2) {
            throw new RuntimeException('Одна из точек маршрута не существует.');
        }
        $baseId = (int)$pdo->query("SELECT id FROM locations WHERE kind='base' ORDER BY id LIMIT 1")->fetchColumn();
        if ($baseId <= 0) {
            throw new RuntimeException('Не настроена база робота.');
        }
        $active = $pdo->prepare('SELECT id FROM missions WHERE robot_id=? AND status NOT IN ("completed","cancelled","failed") LIMIT 1 FOR UPDATE');
        $active->execute([$robotId]);
        if ($active->fetchColumn()) {
            throw new RuntimeException('Для робота уже существует активный заказ.');
        }
        $uid = uuid4();
        $rfidKey = random_bytes(32);
        $stmt = $pdo->prepare('INSERT INTO missions (mission_uid,robot_id,customer_id,pickup_location_id,destination_location_id,base_location_id,cargo_description,shipment_type,sender_name,recipient_name,status,version,pin_hash,pin_encrypted,rfid_verifier_key_encrypted,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,"created",1,?,?,?,NOW(),NOW())');
        $stmt->execute([$uid,$robotId,(int)$user['id'],$pickupId,$destinationId,$baseId,$cargo,$shipmentType,$senderName,$recipientName,password_hash($pin, PASSWORD_BCRYPT, ['cost' => 12]),app_encrypt($pin,'mission-pin'),app_encrypt($rfidKey,'mission-rfid-key')]);
        $missionId = (int)$pdo->lastInsertId();
        if ($shipmentType !== 'oversized' && $rfidIds) {
            $allowed = $pdo->prepare('SELECT id FROM rfid_cards WHERE id=? AND is_active=1 AND uid_hash IS NOT NULL');
            $link = $pdo->prepare('INSERT IGNORE INTO mission_rfid (mission_id,rfid_card_id) VALUES (?,?)');
            foreach ($rfidIds as $cardId) {
                $allowed->execute([$cardId]);
                if ($allowed->fetchColumn()) {
                    $link->execute([$missionId, $cardId]);
                }
            }
        }
        $pdo->prepare('UPDATE robots SET status="reserved" WHERE id=?')->execute([$robotId]);
        $mission = mission_for_user($missionId, $user);
        create_command($mission, 'stage_mission', mission_package($mission));
        add_event($missionId, 'ORDER_CREATED', 'cloud', ['customer_id' => (int)$user['id']]);
        audit_log('mission_created', 'mission', $uid, ['robot_id' => $robotId], (int)$user['id']);
        $pdo->commit();
        flash('success', 'Заказ создан. Edge заберёт его при следующей синхронизации.');
        redirect_to('/missions/' . $missionId);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log('Create mission error: ' . $e->getMessage());
        flash('danger', $e instanceof RuntimeException ? $e->getMessage() : 'Не удалось создать заказ.');
        redirect_to('/missions/new');
    }
}

if ($method === 'GET' && preg_match('#^/missions/(\d+)$#', $path, $match)) {
    $user = require_user();
    $mission = mission_for_user((int)$match[1], $user);
    $stmt = $pdo->prepare('SELECT c.label,c.uid_mask,r.full_name recipient_name FROM mission_rfid mr JOIN rfid_cards c ON c.id=mr.rfid_card_id JOIN recipients r ON r.id=c.recipient_id WHERE mr.mission_id=? ORDER BY r.full_name');
    $stmt->execute([(int)$mission['id']]);
    $cards = $stmt->fetchAll();
    $stmt = $pdo->prepare('SELECT * FROM mission_events WHERE mission_id=? ORDER BY occurred_at DESC,id DESC LIMIT 30');
    $stmt->execute([(int)$mission['id']]);
    $events = $stmt->fetchAll();
    render_header('Заказ ' . substr((string)$mission['mission_uid'], 0, 8), $user);
    page_title('Заказ ' . substr((string)$mission['mission_uid'], 0, 8), $mission['pickup_name'] . ' → ' . $mission['destination_name'], '<a class="button secondary" href="' . h(base_url('/dashboard')) . '">К списку</a>');
    ?>
    <div class="split" data-mission-poll="<?= h(base_url('/api/missions/' . $mission['id'])) ?>" data-csrf="<?= h(csrf_token()) ?>" data-mission-id="<?= (int)$mission['id'] ?>">
        <div class="stack"><section class="card card-pad">
            <div class="item-card-head"><div><span class="muted">Текущий статус</span><h2><span data-mission-status class="<?= h(mission_status_class((string)$mission['status'])) ?>"><?= h(status_label((string)$mission['status'])) ?></span></h2></div><span class="mono muted"><?= h($mission['mission_uid']) ?></span></div>
            <div class="detail-list section"><div><span>Робот</span><strong><?= h($mission['robot_name']) ?></strong></div><div><span>Клиент</span><strong><?= h($mission['customer_name']) ?></strong></div><div><span>Отправитель</span><strong><?= h($mission['sender_name']) ?></strong></div><div><span>Получатель</span><strong><?= h($mission['recipient_name']) ?></strong></div><div><span>Тип</span><strong><?= $mission['shipment_type']==='oversized'?'Негабарит':'Габарит' ?></strong></div><div><span>Погрузка</span><strong><?= h($mission['pickup_name']) ?></strong></div><div><span>Доставка</span><strong><?= h($mission['destination_name']) ?></strong></div><div><span>Возврат</span><strong><?= h($mission['base_name']) ?></strong></div><div><span>Обновлено</span><strong data-mission-updated><?= h(format_dt($mission['updated_at'])) ?></strong></div><div class="wide"><span>Груз</span><strong><?= h($mission['cargo_description']) ?></strong></div></div>
            <div class="section pin-box"><div><span>Резервный PIN</span><p class="muted">Видит только создатель заказа и администратор</p></div><code><?= h(app_decrypt((string)$mission['pin_encrypted'], 'mission-pin')) ?></code></div>
            <div class="section"><span class="muted">Разрешённые RFID</span><div class="chips"><?php if (!$cards): ?><span class="chip">Не выбраны — доступен PIN</span><?php endif; ?><?php foreach ($cards as $card): ?><span class="chip"><?= h($card['recipient_name']) ?> · <?= h($card['label']) ?> · <span class="mono"><?= h($card['uid_mask']) ?></span></span><?php endforeach; ?></div></div>
            <div class="actions" data-mission-actions><?php foreach (mission_allowed_actions($mission) as $action): ?><?php if ($action === 'confirm_loaded'): ?><form method="post" action="<?= h(base_url('/missions/' . $mission['id'] . '/confirm-loaded')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="version" value="<?= (int)$mission['version'] ?>"><button class="button primary" type="submit">Погрузка завершена — старт</button></form><?php elseif ($action === 'cancel'): ?><form method="post" action="<?= h(base_url('/missions/' . $mission['id'] . '/cancel')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="version" value="<?= (int)$mission['version'] ?>"><button class="button danger" data-confirm="Отменить заказ?" type="submit">Отменить</button></form><?php endif; ?><?php endforeach; ?></div>
        </section></div>
        <aside class="card card-pad"><div class="section-title"><h2>Журнал событий</h2></div><ol class="timeline" data-event-list><?php foreach ($events as $event): ?><li><span class="event-dot"></span><div><strong><?= h(event_label((string)$event['event_type'])) ?></strong><small><?= h($event['source']) ?> · <?= h(format_dt($event['occurred_at'])) ?></small></div></li><?php endforeach; ?></ol></aside>
    </div>
    <?php render_footer(); exit;
}

if ($method === 'POST' && preg_match('#^/missions/(\d+)/confirm-loaded$#', $path, $match)) {
    verify_csrf();
    $user = require_user();
    $expectedVersion = (int)($_POST['version'] ?? 0);
    $pdo->beginTransaction();
    try {
        $mission = mission_for_user((int)$match[1], $user, true);
        if ($mission['status'] !== 'waiting_for_loading' || (int)$mission['version'] !== $expectedVersion) {
            throw new RuntimeException('Заказ уже изменён другим пользователем. Обновите страницу.');
        }
        $updated = $pdo->prepare('UPDATE missions SET status="start_requested",version=version+1 WHERE id=? AND version=? AND status="waiting_for_loading"');
        $updated->execute([(int)$mission['id'], $expectedVersion]);
        if ($updated->rowCount() !== 1) {
            throw new RuntimeException('Состояние заказа изменилось.');
        }
        create_command($mission, 'start_mission', ['schema_version' => '2.1', 'mission_id' => $mission['mission_uid']], 3600);
        add_event((int)$mission['id'], 'LOADING_CONFIRMED', 'cloud', ['customer_id' => (int)$user['id']]);
        audit_log('mission_start_requested', 'mission', $mission['mission_uid'], [], (int)$user['id']);
        $pdo->commit();
        flash('success', 'Команда запуска поставлена в очередь.');
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        flash('warning', $e instanceof RuntimeException ? $e->getMessage() : 'Не удалось запустить заказ.');
    }
    redirect_to('/missions/' . (int)$match[1]);
}

if ($method === 'POST' && preg_match('#^/missions/(\d+)/cancel$#', $path, $match)) {
    verify_csrf();
    $user = require_user();
    $expectedVersion = (int)($_POST['version'] ?? 0);
    $pdo->beginTransaction();
    try {
        $mission = mission_for_user((int)$match[1], $user, true);
        if (in_array($mission['status'], TERMINAL_MISSION_STATUSES, true) || $mission['status'] === 'cancel_requested' || (int)$mission['version'] !== $expectedVersion) {
            throw new RuntimeException('Заказ уже изменён или завершён.');
        }
        $stmt = $pdo->prepare('UPDATE missions SET status="cancel_requested",cancel_requested_at=NOW(),version=version+1 WHERE id=? AND version=?');
        $stmt->execute([(int)$mission['id'], $expectedVersion]);
        if ($stmt->rowCount() !== 1) {
            throw new RuntimeException('Состояние заказа изменилось.');
        }
        create_command($mission, 'cancel_mission', ['schema_version' => '2.1', 'mission_id' => $mission['mission_uid']], null);
        add_event((int)$mission['id'], 'CANCEL_REQUESTED', 'cloud', ['customer_id' => (int)$user['id']]);
        audit_log('mission_cancel_requested', 'mission', $mission['mission_uid'], [], (int)$user['id']);
        $pdo->commit();
        flash('success', 'Запрос отмены отправлен. Статус станет «Отменён» после подтверждения роботом.');
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        flash('warning', $e instanceof RuntimeException ? $e->getMessage() : 'Не удалось отменить заказ.');
    }
    redirect_to('/missions/' . (int)$match[1]);
}

if ($path === '/admin/requests' && $method === 'GET') {
    $user = require_admin();
    $requests = $pdo->query('SELECT * FROM access_requests ORDER BY created_at DESC')->fetchAll();
    render_header('Заявки', $user, 'requests');
    page_title('Заявки на доступ', 'После одобрения пользователь входит с паролем, указанным в заявке');
    ?><div data-revision-scope="requests" data-revision="<?= h(page_revision($user, 'requests')) ?>"></div><div class="stack"><?php if (!$requests) empty_state('Заявок нет', 'Новые заявки появятся здесь.'); ?><?php foreach ($requests as $request): ?><article class="card item-card"><div class="item-card-head"><div><h3><?= h($request['full_name']) ?></h3><p><?= h($request['email']) ?> · <?= h($request['organization']) ?></p></div><span class="<?= $request['status']==='approved'?'status success':($request['status']==='rejected'?'status danger':'status progress') ?>"><?= h($request['status']) ?></span></div><p class="section"><?= nl2br(h($request['reason'])) ?></p><?php if ($request['status']==='pending'): ?><div class="actions"><form method="post" action="<?= h(base_url('/admin/requests/'.$request['id'].'/approve')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><button class="button primary small" type="submit" <?= empty($request['password_hash'])?'disabled':'' ?>>Одобрить</button></form><form method="post" action="<?= h(base_url('/admin/requests/'.$request['id'].'/reject')) ?>" class="inline-form"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><label>Комментарий<input name="admin_comment" maxlength="1000"></label><button class="button danger small" type="submit">Отклонить</button></form></div><?php if (empty($request['password_hash'])): ?><div class="alert warning section">Старая заявка без пароля. Попросите пользователя подать её заново.</div><?php endif; ?><?php endif; ?></article><?php endforeach; ?></div><?php render_footer(); exit;
}

if ($method === 'POST' && preg_match('#^/admin/requests/(\d+)/approve$#', $path, $match)) {
    verify_csrf();
    $admin = require_admin();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM access_requests WHERE id=? FOR UPDATE');
        $stmt->execute([(int)$match[1]]);
        $request = $stmt->fetch();
        if (!$request || $request['status'] !== 'pending') throw new RuntimeException('Заявка уже обработана.');
        if (empty($request['password_hash'])) throw new RuntimeException('Это старая заявка без пароля. Попросите подать новую.');
        $email = normalize_email((string)$request['email']);
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email=? FOR UPDATE');
        $stmt->execute([$email]);
        $existing = $stmt->fetch();
        if ($existing && (int)$existing['is_active'] === 1) throw new RuntimeException('Активный аккаунт уже существует.');
        if ($existing) {
            $pdo->prepare('UPDATE users SET full_name=?,password_hash=?,role=IF(role="admin","admin","customer"),is_active=1,activation_token=NULL,password_changed_at=NOW() WHERE id=?')->execute([$request['full_name'],$request['password_hash'],(int)$existing['id']]);
            $userId = (int)$existing['id'];
        } else {
            $pdo->prepare('INSERT INTO users (email,full_name,password_hash,role,is_active,password_changed_at,created_at) VALUES (?,?,?,"customer",1,NOW(),NOW())')->execute([$email,$request['full_name'],$request['password_hash']]);
            $userId = (int)$pdo->lastInsertId();
        }
        $pdo->prepare('UPDATE access_requests SET status="approved",password_hash=NULL,reviewed_at=NOW() WHERE id=?')->execute([(int)$request['id']]);
        audit_log('access_request_approved', 'access_request', (string)$request['id'], ['user_id'=>$userId], (int)$admin['id']);
        $pdo->commit();
        flash('success', 'Заявка одобрена. Пользователь может войти со своим паролем.');
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        flash('danger', $e instanceof RuntimeException ? $e->getMessage() : 'Не удалось одобрить заявку.');
    }
    redirect_to('/admin/requests');
}

if ($method === 'POST' && preg_match('#^/admin/requests/(\d+)/reject$#', $path, $match)) {
    verify_csrf();
    $admin = require_admin();
    $stmt = $pdo->prepare('UPDATE access_requests SET status="rejected",password_hash=NULL,admin_comment=?,reviewed_at=NOW() WHERE id=? AND status="pending"');
    $stmt->execute([trim((string)($_POST['admin_comment'] ?? '')),(int)$match[1]]);
    if ($stmt->rowCount() === 1) {
        audit_log('access_request_rejected', 'access_request', $match[1], [], (int)$admin['id']);
        flash('success', 'Заявка отклонена.');
    } else {
        flash('warning', 'Заявка уже обработана или не найдена.');
    }
    redirect_to('/admin/requests');
}

if ($path === '/admin/users' && $method === 'GET') {
    $user = require_admin();
    $users = $pdo->query('SELECT * FROM users ORDER BY created_at DESC')->fetchAll();
    render_header('Пользователи', $user, 'users'); page_title('Пользователи', 'Клиенты регистрируются только после подтверждения администратора');
    ?><div data-revision-scope="users" data-revision="<?= h(page_revision($user, 'users')) ?>"></div><div class="stack"><?php foreach ($users as $item): ?><article class="card item-card"><div class="item-card-head"><div><h3><?= h($item['full_name']) ?></h3><p><?= h($item['email']) ?> · <?= $item['role']==='admin'?'Администратор':'Клиент' ?></p></div><span class="<?= $item['is_active']?'status success':'status danger' ?>"><?= $item['is_active']?'Активен':'Отключён' ?></span></div><div class="actions"><?php if((int)$item['id']!==(int)$user['id']): ?><form method="post" action="<?= h(base_url('/admin/users/'.$item['id'].'/role')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><input type="hidden" name="role" value="<?= $item['role']==='admin'?'customer':'admin' ?>"><button class="button secondary small" type="submit"><?= $item['role']==='admin'?'Сделать клиентом':'Назначить администратором' ?></button></form><?php if($item['role']==='customer'): ?><form method="post" action="<?= h(base_url('/admin/users/'.$item['id'].'/delete')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><button class="button danger small" data-confirm="Удалить клиента? При наличии заказов аккаунт будет отключён с сохранением истории." type="submit">Удалить клиента</button></form><?php endif; ?><?php endif; ?></div></article><?php endforeach; ?></div><?php render_footer(); exit;
}

if ($method==='POST' && preg_match('#^/admin/users/(\d+)/role$#',$path,$match)) {
    verify_csrf(); $admin=require_admin(); $targetId=(int)$match[1]; $role=(string)($_POST['role']??'');
    try { if($targetId===(int)$admin['id'] || !in_array($role,['admin','customer'],true)) throw new RuntimeException('Недопустимое изменение роли.');
        $pdo->beginTransaction(); $stmt=$pdo->prepare('SELECT role FROM users WHERE id=? FOR UPDATE');$stmt->execute([$targetId]);$old=(string)$stmt->fetchColumn();if($old==='')throw new RuntimeException('Пользователь не найден.');
        if($old==='admin' && $role==='customer' && (int)$pdo->query('SELECT COUNT(*) FROM users WHERE role="admin" AND is_active=1')->fetchColumn()<=1)throw new RuntimeException('Нельзя снять права у последнего администратора.');
        $pdo->prepare('UPDATE users SET role=? WHERE id=?')->execute([$role,$targetId]);audit_log('user_role_changed','user',(string)$targetId,['from'=>$old,'to'=>$role],(int)$admin['id']);$pdo->commit();flash('success','Роль пользователя изменена.');
    } catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();flash('danger',$e instanceof RuntimeException?$e->getMessage():'Не удалось изменить роль.');} redirect_to('/admin/users');
}

if ($method==='POST' && preg_match('#^/admin/users/(\d+)/delete$#',$path,$match)) {
    verify_csrf(); $admin=require_admin(); $targetId=(int)$match[1];
    try { $pdo->beginTransaction();$stmt=$pdo->prepare('SELECT role FROM users WHERE id=? FOR UPDATE');$stmt->execute([$targetId]);$role=(string)$stmt->fetchColumn();if($role!=='customer')throw new RuntimeException('Удалять можно только клиентов.');
        $count=$pdo->prepare('SELECT COUNT(*) FROM missions WHERE customer_id=?');$count->execute([$targetId]);
        if((int)$count->fetchColumn()>0){$pdo->prepare('UPDATE users SET is_active=0 WHERE id=?')->execute([$targetId]);$result='Аккаунт отключён, история заказов сохранена.';}else{$pdo->prepare('DELETE FROM users WHERE id=?')->execute([$targetId]);$result='Клиент удалён.';}
        audit_log('customer_deleted','user',(string)$targetId,[],(int)$admin['id']);$pdo->commit();flash('success',$result);
    }catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();flash('danger',$e instanceof RuntimeException?$e->getMessage():'Не удалось удалить клиента.');}redirect_to('/admin/users');
}

if ($path === '/admin/security' && $method === 'GET') {
    $user = require_admin();
    $edges = $pdo->query('SELECT id,edge_id,name,last_seen_at FROM edge_gateways ORDER BY name')->fetchAll();
    $robots = $pdo->query('SELECT id,robot_uid,name,robot_key_version,last_robot_seen_at FROM robots ORDER BY name')->fetchAll();
    $secret = $_SESSION['one_time_secret'] ?? null;
    unset($_SESSION['one_time_secret']);
    render_header('Безопасность', $user, 'security');
    page_title('Ключи и токены', 'Секреты показываются только один раз после ротации');
    if (is_array($secret)): ?>
        <section class="alert warning"><strong><?= h((string)$secret['title']) ?></strong><p>Скопируйте значение сейчас и сохраните в защищённом месте. После обновления страницы оно исчезнет.</p><code class="secret-code"><?= h((string)$secret['value']) ?></code></section>
    <?php endif; ?>
    <section class="section"><div class="section-title"><h2>Edge-серверы</h2></div><div class="stack">
    <?php foreach ($edges as $edge): ?><article class="card item-card"><div class="item-card-head"><div><h3><?= h($edge['name']) ?></h3><p class="mono"><?= h($edge['edge_id']) ?></p></div><span class="muted"><?= h(format_dt($edge['last_seen_at'])) ?></span></div><form method="post" action="<?= h(base_url('/admin/security/edge/'.$edge['id'].'/rotate-token')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><button class="button danger small" data-confirm="Старый Edge token немедленно перестанет работать. Продолжить?" type="submit">Сменить Edge token</button></form></article><?php endforeach; ?>
    </div></section>
    <section class="section"><div class="section-title"><h2>Ключи Jetson Nano</h2></div><div class="stack">
    <?php foreach ($robots as $robot): ?><article class="card item-card"><div class="item-card-head"><div><h3><?= h($robot['name']) ?></h3><p class="mono"><?= h($robot['robot_uid']) ?> · версия ключа <?= (int)$robot['robot_key_version'] ?></p></div><span class="muted"><?= h(format_dt($robot['last_robot_seen_at'])) ?></span></div><form method="post" action="<?= h(base_url('/admin/security/robots/'.$robot['id'].'/rotate-key')) ?>"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><button class="button danger small" data-confirm="После смены ключа нужно обновить ROBOT_ACCESS_KEY на Jetson Nano. Продолжить?" type="submit">Сменить ключ доступа</button></form></article><?php endforeach; ?>
    </div></section>
    <?php render_footer(); exit;
}

if ($method === 'POST' && preg_match('#^/admin/security/edge/(\d+)/rotate-token$#', $path, $match)) {
    verify_csrf();
    $admin = require_admin();
    $stmt = $pdo->prepare('SELECT edge_id FROM edge_gateways WHERE id=?');
    $stmt->execute([(int)$match[1]]);
    $edgeId = (string)$stmt->fetchColumn();
    if ($edgeId === '') {
        flash('danger', 'Edge-сервер не найден.');
        redirect_to('/admin/security');
    }
    $token = random_secret_b64(32);
    $pdo->prepare('UPDATE edge_gateways SET token_hash=? WHERE id=?')->execute([
        high_entropy_token_hash('edge-token:' . $edgeId, $token),
        (int)$match[1],
    ]);
    audit_log('edge_token_rotated', 'edge_gateway', $edgeId, [], (int)$admin['id']);
    $_SESSION['one_time_secret'] = ['title' => 'Новый Edge token для ' . $edgeId, 'value' => $token];
    redirect_to('/admin/security');
}

if ($method === 'POST' && preg_match('#^/admin/security/robots/(\d+)/rotate-key$#', $path, $match)) {
    verify_csrf();
    $admin = require_admin();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM robots WHERE id=? FOR UPDATE');
        $stmt->execute([(int)$match[1]]);
        $robot = $stmt->fetch();
        if (!$robot) {
            throw new RuntimeException('Робот не найден.');
        }
        $active = $pdo->prepare('SELECT id FROM missions WHERE robot_id=? AND status NOT IN ("completed","cancelled","failed") LIMIT 1 FOR UPDATE');
        $active->execute([(int)$robot['id']]);
        if ($active->fetchColumn()) {
            throw new RuntimeException('Нельзя менять ключ во время активного заказа.');
        }
        $rawKey = random_bytes(32);
        $pdo->prepare('UPDATE robots SET robot_access_key_encrypted=?,robot_key_version=robot_key_version+1 WHERE id=?')->execute([
            app_encrypt($rawKey, 'robot-access-key'),
            (int)$robot['id'],
        ]);
        audit_log('robot_access_key_rotated', 'robot', (string)$robot['robot_uid'], [], (int)$admin['id']);
        $pdo->commit();
        $_SESSION['one_time_secret'] = ['title' => 'Новый ROBOT_ACCESS_KEY для ' . $robot['robot_uid'], 'value' => rtrim(strtr(base64_encode($rawKey), '+/', '-_'), '=')];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        flash('danger', $e instanceof RuntimeException ? $e->getMessage() : 'Не удалось сменить ключ.');
    }
    redirect_to('/admin/security');
}

if ($path === '/recipients' && $method === 'GET') {
    $user = require_admin();
    $recipients = $pdo->query('SELECT * FROM recipients ORDER BY full_name')->fetchAll();
    $cardsByRecipient=[];
    foreach ($pdo->query('SELECT id,label,recipient_id,is_active,uid_mask FROM rfid_cards ORDER BY label')->fetchAll() as $card) $cardsByRecipient[(int)$card['recipient_id']][]=$card;
    render_header('Получатели и RFID',$user,'recipients'); page_title('Получатели и RFID','Полные UID зашифрованы и никогда не показываются в интерфейсе');
    ?><div data-revision-scope="recipients" data-revision="<?= h(page_revision($user,'recipients')) ?>"></div><section class="card card-pad"><form method="post" action="<?= h(base_url('/recipients')) ?>" class="form-grid"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><label>ФИО<input name="full_name" maxlength="255" required></label><label>Подразделение<input name="department" maxlength="255"></label><button class="button primary wide" type="submit">Добавить получателя</button></form></section><div class="stack section"><?php foreach ($recipients as $recipient): ?><article class="card item-card"><div class="item-card-head"><div><h3><?= h($recipient['full_name']) ?></h3><p><?= h($recipient['department']) ?></p></div></div><div class="stack section"><?php foreach (($cardsByRecipient[(int)$recipient['id']]??[]) as $card): ?><form method="post" action="<?= h(base_url('/rfid/'.$card['id'].'/update')) ?>" class="inline-form"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><label>Название<input name="label" maxlength="255" value="<?= h($card['label']) ?>" required></label><label>Новый UID, если меняется<input name="uid" maxlength="64" placeholder="Оставьте пустым"></label><label class="check-row"><input type="checkbox" name="is_active" value="1" <?= $card['is_active']?'checked':'' ?>> Активна</label><span class="mono"><?= h($card['uid_mask']) ?></span><button class="button secondary small" type="submit">Сохранить</button><button class="button danger small" type="submit" formaction="<?= h(base_url('/rfid/'.$card['id'].'/delete')) ?>" data-confirm="Удалить RFID-карту? Использованная карта будет отключена с сохранением истории.">Удалить</button></form><?php endforeach; ?></div><form method="post" action="<?= h(base_url('/recipients/'.$recipient['id'].'/cards')) ?>" class="inline-form"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><label>UID карты<input name="uid" maxlength="64" required></label><label>Название<input name="label" maxlength="255" required></label><button class="button secondary small" type="submit">Добавить RFID</button></form></article><?php endforeach; ?></div><?php render_footer(); exit;
}

if ($path === '/recipients' && $method === 'POST') {
    verify_csrf(); $admin=require_admin(); $fullName=trim((string)($_POST['full_name']??'')); if($fullName===''){flash('danger','Укажите ФИО.');redirect_to('/recipients');}
    $pdo->prepare('INSERT INTO recipients (full_name,department,created_at,updated_at) VALUES (?,?,NOW(),NOW())')->execute([$fullName,trim((string)($_POST['department']??''))]); audit_log('recipient_created','recipient',(string)$pdo->lastInsertId(),[],(int)$admin['id']); flash('success','Получатель добавлен.'); redirect_to('/recipients');
}

if ($method === 'POST' && preg_match('#^/recipients/(\d+)/cards$#',$path,$match)) {
    verify_csrf(); $admin=require_admin(); $label=trim((string)($_POST['label']??''));
    try {
        $uid=normalize_rfid_uid((string)($_POST['uid']??''));
        if($label==='') throw new InvalidArgumentException('Укажите название карты.');
        $stmt=$pdo->prepare('INSERT INTO rfid_cards (uid,uid_hash,uid_encrypted,uid_mask,label,recipient_id,is_active,created_at,updated_at) SELECT NULL,?,?,?,?,?,1,NOW(),NOW() FROM recipients WHERE id=?');
        $stmt->execute([rfid_uid_hash($uid),app_encrypt($uid,'rfid-card'),mask_rfid_uid($uid),$label,(int)$match[1],(int)$match[1]]);
        if($stmt->rowCount()!==1) throw new RuntimeException('Получатель не найден.');
        audit_log('rfid_created','rfid_card',(string)$pdo->lastInsertId(),['uid_mask'=>mask_rfid_uid($uid)],(int)$admin['id']); flash('success','RFID-карта добавлена и зашифрована.');
    } catch(PDOException $e){
        error_log('RFID insert error: ' . $e->getMessage());
        flash('danger', (string)$e->getCode()==='23000' ? 'Такая RFID-карта уже существует.' : 'Не удалось сохранить RFID-карту.');
    } catch(Throwable $e){flash('danger',$e->getMessage());}
    redirect_to('/recipients');
}

if ($method==='POST' && preg_match('#^/rfid/(\d+)/update$#',$path,$match)) {
    verify_csrf();$admin=require_admin();$id=(int)$match[1];$label=trim((string)($_POST['label']??''));$uidInput=trim((string)($_POST['uid']??''));$active=isset($_POST['is_active'])?1:0;
    try{if($label==='')throw new RuntimeException('Укажите название карты.');$fields=['label=?','is_active=?'];$params=[$label,$active];if($uidInput!==''){$uid=normalize_rfid_uid($uidInput);$fields[]='uid_hash=?';$fields[]='uid_encrypted=?';$fields[]='uid_mask=?';$params[]=rfid_uid_hash($uid);$params[]=app_encrypt($uid,'rfid-card');$params[]=mask_rfid_uid($uid);}$params[]=$id;$pdo->prepare('UPDATE rfid_cards SET '.implode(',',$fields).' WHERE id=?')->execute($params);audit_log('rfid_updated','rfid_card',(string)$id,['active'=>$active],(int)$admin['id']);flash('success','RFID-карта обновлена.');}catch(PDOException $e){flash('danger',(string)$e->getCode()==='23000'?'Такой UID уже используется.':'Не удалось обновить карту.');}catch(Throwable $e){flash('danger',$e->getMessage());}redirect_to('/recipients');
}

if ($method==='POST' && preg_match('#^/rfid/(\d+)/delete$#',$path,$match)) {
    verify_csrf();$admin=require_admin();$id=(int)$match[1];try{$pdo->beginTransaction();$used=$pdo->prepare('SELECT COUNT(*) FROM mission_rfid WHERE rfid_card_id=?');$used->execute([$id]);if((int)$used->fetchColumn()>0){$pdo->prepare('UPDATE rfid_cards SET is_active=0 WHERE id=?')->execute([$id]);$message='RFID отключена, история заказов сохранена.';}else{$pdo->prepare('DELETE FROM rfid_cards WHERE id=?')->execute([$id]);$message='RFID-карта удалена.';}audit_log('rfid_deleted','rfid_card',(string)$id,[],(int)$admin['id']);$pdo->commit();flash('success',$message);}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();flash('danger','Не удалось удалить RFID-карту.');}redirect_to('/recipients');
}

if ($path === '/admin/map' && $method === 'GET') {
    $admin = require_admin();
    $map = $pdo->query('SELECT * FROM facility_maps WHERE is_active=1 ORDER BY id DESC LIMIT 1')->fetch();
    $mapJson = $map ? (string)$map['map_json'] : json_encode(['roads'=>[],'signs'=>[],'traffic_lights'=>[]], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    render_header('Векторная карта', $admin, 'map'); page_title('Карта объекта', 'Дороги задаются линиями, знаки и светофоры — точечными объектами. Карта отправляется на Edge с каждым заказом.');
    ?><section class="card card-pad"><form method="post" action="<?= h(base_url('/admin/map')) ?>" class="form-stack"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><label>Название карты<input name="name" maxlength="255" value="<?= h($map['name'] ?? 'Основная карта') ?>" required></label><label>Векторные слои JSON<textarea name="map_json" class="map-json" required><?= h($mapJson) ?></textarea></label><div class="alert info">Формат: <code>roads</code> — массив линий с точками <code>[[x,y],...]</code>; <code>signs</code> и <code>traffic_lights</code> — массивы объектов с координатами.</div><button class="button primary" type="submit">Сохранить новую версию карты</button></form></section><?php render_footer(); exit;
}

if ($path === '/admin/map' && $method === 'POST') {
    verify_csrf(); $admin=require_admin(); $name=trim((string)($_POST['name']??'')); $raw=(string)($_POST['map_json']??'');
    try {
        $data=json_decode($raw,true,512,JSON_THROW_ON_ERROR);
        if(!is_array($data) || !isset($data['roads'],$data['signs'],$data['traffic_lights']) || !is_array($data['roads']) || !is_array($data['signs']) || !is_array($data['traffic_lights'])) throw new RuntimeException('Нужны массивы roads, signs и traffic_lights.');
        if(strlen($raw)>1048576 || $name==='') throw new RuntimeException('Проверьте название и размер карты.');
        $pdo->beginTransaction(); $pdo->exec('UPDATE facility_maps SET is_active=0 WHERE is_active=1');
        $version=(int)$pdo->query('SELECT COALESCE(MAX(version),0)+1 FROM facility_maps')->fetchColumn();
        $pdo->prepare('INSERT INTO facility_maps(name,version,map_json,is_active,updated_at) VALUES (?,?,?,1,NOW())')->execute([$name,$version,json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)]);
        audit_log('facility_map_saved','facility_map',(string)$pdo->lastInsertId(),['version'=>$version],(int)$admin['id']); $pdo->commit(); flash('success','Карта сохранена. Версия '.$version.' будет отправляться на Edge.');
    } catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();flash('danger',$e instanceof RuntimeException?$e->getMessage():'Некорректный JSON карты.');}
    redirect_to('/admin/map');
}

http_response_code(404);
$user=current_user(); render_header('Страница не найдена',$user?:null); ?><section class="card auth-card"><h1>404</h1><p class="muted">Страница не найдена.</p><a class="button primary" href="<?= h(base_url($user?'/dashboard':'/login')) ?>">Вернуться</a></section><?php render_footer();
