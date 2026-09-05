<?php
declare(strict_types=1);
require __DIR__ . '/inc/bootstrap.php';
$admin = require_admin();

function column_exists(PDO $pdo, string $table, string $column): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?');
    $stmt->execute([$table, $column]);
    return (int)$stmt->fetchColumn() > 0;
}
function index_exists(PDO $pdo, string $table, string $index): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND INDEX_NAME=?');
    $stmt->execute([$table, $index]);
    return (int)$stmt->fetchColumn() > 0;
}
function add_column(PDO $pdo, string $table, string $column, string $definition): void
{
    if (!column_exists($pdo, $table, $column)) {
        $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
    }
}

$error = '';
$done = false;
$messages = [];
$robotKeys = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    try {
        $pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (migration_id VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci');
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM schema_migrations WHERE migration_id=?');
        $stmt->execute(['secure-v0.5']);
        if ((int)$stmt->fetchColumn() > 0) {
            throw new RuntimeException('Обновление secure-v0.5 уже применено. Удалите upgrade.php.');
        }

        add_column($pdo, 'users', 'activation_expires_at', 'DATETIME NULL');
        add_column($pdo, 'users', 'last_login_at', 'DATETIME NULL');
        add_column($pdo, 'users', 'password_changed_at', 'DATETIME NULL');
        add_column($pdo, 'access_requests', 'password_hash', 'VARCHAR(255) NULL');
        add_column($pdo, 'access_requests', 'submit_ip_hash', 'CHAR(64) NULL');
        add_column($pdo, 'robots', 'telemetry_status', 'VARCHAR(50) NOT NULL DEFAULT "offline"');
        add_column($pdo, 'robots', 'last_robot_seen_at', 'DATETIME NULL');
        add_column($pdo, 'robots', 'robot_access_key_encrypted', 'TEXT NULL');
        add_column($pdo, 'robots', 'robot_key_version', 'INT UNSIGNED NOT NULL DEFAULT 1');
        add_column($pdo, 'recipients', 'updated_at', 'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
        add_column($pdo, 'rfid_cards', 'uid_hash', 'CHAR(64) NULL');
        add_column($pdo, 'rfid_cards', 'uid_encrypted', 'TEXT NULL');
        add_column($pdo, 'rfid_cards', 'uid_mask', 'VARCHAR(32) NOT NULL DEFAULT "••••"');
        add_column($pdo, 'rfid_cards', 'updated_at', 'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
        add_column($pdo, 'missions', 'version', 'INT UNSIGNED NOT NULL DEFAULT 1');
        add_column($pdo, 'missions', 'last_event_sequence', 'BIGINT UNSIGNED NOT NULL DEFAULT 0');
        add_column($pdo, 'missions', 'rfid_verifier_key_encrypted', 'TEXT NULL');
        add_column($pdo, 'missions', 'cancel_requested_at', 'DATETIME NULL');
        add_column($pdo, 'missions', 'shipment_type', 'ENUM("standard","oversized","mixed") NOT NULL DEFAULT "standard"');
        add_column($pdo, 'missions', 'sender_name', 'VARCHAR(255) NOT NULL DEFAULT ""');
        add_column($pdo, 'missions', 'recipient_name', 'VARCHAR(255) NOT NULL DEFAULT ""');
        $pdo->exec('UPDATE users SET role="customer" WHERE role="operator"');
        $pdo->exec('ALTER TABLE users MODIFY role ENUM("admin","customer") NOT NULL DEFAULT "customer"');
        add_column($pdo, 'mission_events', 'sequence_number', 'BIGINT UNSIGNED NULL');
        add_column($pdo, 'edge_commands', 'expires_at', 'DATETIME NULL');

        $pdo->exec('ALTER TABLE rfid_cards MODIFY uid VARCHAR(100) NULL');
        $pdo->exec('ALTER TABLE edge_commands MODIFY status ENUM("pending","acked","rejected","cancelled","expired") NOT NULL DEFAULT "pending"');

        if (!index_exists($pdo, 'rfid_cards', 'uq_rfid_uid_hash')) {
            $pdo->exec('CREATE UNIQUE INDEX uq_rfid_uid_hash ON rfid_cards(uid_hash)');
        }
        if (!index_exists($pdo, 'mission_events', 'uq_event_mission_sequence')) {
            $pdo->exec('CREATE UNIQUE INDEX uq_event_mission_sequence ON mission_events(mission_id,sequence_number)');
        }
        if (!index_exists($pdo, 'robots', 'idx_robot_status')) {
            $pdo->exec('CREATE INDEX idx_robot_status ON robots(status)');
        }

        $pdo->exec('CREATE TABLE IF NOT EXISTS rate_limits (bucket_key CHAR(64) PRIMARY KEY,attempts INT UNSIGNED NOT NULL DEFAULT 0,window_started_at DATETIME NOT NULL,blocked_until DATETIME NULL,updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci');
        $pdo->exec('CREATE TABLE IF NOT EXISTS audit_logs (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,user_id BIGINT UNSIGNED NULL,action VARCHAR(100) NOT NULL,entity_type VARCHAR(80) NULL,entity_id VARCHAR(100) NULL,ip_hash CHAR(64) NULL,details_json LONGTEXT NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,INDEX idx_audit_created(created_at),INDEX idx_audit_action(action),CONSTRAINT fk_audit_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci');

        // UID RFID: нормализация, HMAC для уникальности и AES-GCM для хранения.
        $cards = $pdo->query('SELECT id,uid,uid_hash,uid_encrypted FROM rfid_cards ORDER BY id')->fetchAll();
        $seen = [];
        foreach ($cards as $card) {
            $raw = '';
            if (!empty($card['uid_encrypted'])) {
                $raw = app_decrypt((string)$card['uid_encrypted'], 'rfid-card');
            }
            if ($raw === '' && !empty($card['uid'])) {
                try { $raw = normalize_rfid_uid((string)$card['uid']); } catch (Throwable $e) { $raw = ''; }
            }
            if ($raw === '') {
                $pdo->prepare('UPDATE rfid_cards SET is_active=0,uid=NULL WHERE id=?')->execute([(int)$card['id']]);
                $messages[] = 'RFID #' . (int)$card['id'] . ' отключён: UID не удалось безопасно мигрировать.';
                continue;
            }
            $hash = rfid_uid_hash($raw);
            if (isset($seen[$hash])) {
                $pdo->prepare('UPDATE rfid_cards SET is_active=0,uid=NULL,uid_hash=NULL,uid_encrypted=NULL,uid_mask=? WHERE id=?')->execute([mask_rfid_uid($raw) . ' duplicate', (int)$card['id']]);
                $messages[] = 'Дубликат RFID #' . (int)$card['id'] . ' отключён.';
                continue;
            }
            $seen[$hash] = true;
            $pdo->prepare('UPDATE rfid_cards SET uid=NULL,uid_hash=?,uid_encrypted=?,uid_mask=? WHERE id=?')->execute([$hash, app_encrypt($raw, 'rfid-card'), mask_rfid_uid($raw), (int)$card['id']]);
        }

        // PIN и индивидуальные ключи миссий.
        $missions = $pdo->query('SELECT id,pin_encrypted,rfid_verifier_key_encrypted FROM missions')->fetchAll();
        foreach ($missions as $mission) {
            $pin = app_decrypt((string)$mission['pin_encrypted'], 'mission-pin');
            if ($pin === '') { $pin = app_decrypt((string)$mission['pin_encrypted']); }
            $updates = [];
            $params = [];
            if ($pin !== '') { $updates[] = 'pin_encrypted=?'; $params[] = app_encrypt($pin, 'mission-pin'); }
            if (empty($mission['rfid_verifier_key_encrypted'])) { $updates[] = 'rfid_verifier_key_encrypted=?'; $params[] = app_encrypt(random_bytes(32), 'mission-rfid-key'); }
            if ($updates) { $params[] = (int)$mission['id']; $pdo->prepare('UPDATE missions SET ' . implode(',', $updates) . ' WHERE id=?')->execute($params); }
        }

        // Новый сквозной ключ доступа создаётся отдельно для каждого робота.
        $robots = $pdo->query('SELECT id,robot_uid,robot_access_key_encrypted,robot_key_version FROM robots ORDER BY id')->fetchAll();
        foreach ($robots as $robot) {
            $existing = app_decrypt((string)($robot['robot_access_key_encrypted'] ?? ''), 'robot-access-key');
            if ($existing === '' || strlen($existing) !== 32) {
                $rawKey = random_bytes(32);
                $pdo->prepare('UPDATE robots SET robot_access_key_encrypted=?,robot_key_version=robot_key_version+1 WHERE id=?')->execute([app_encrypt($rawKey, 'robot-access-key'), (int)$robot['id']]);
                $robotKeys[(string)$robot['robot_uid']] = rtrim(strtr(base64_encode($rawKey), '+/', '-_'), '=');
            }
        }

        $pdo->exec('UPDATE access_requests SET admin_comment=COALESCE(admin_comment,"Старая заявка без пароля — попросите подать заново") WHERE status="pending" AND password_hash IS NULL');
        $pdo->exec('UPDATE access_requests SET password_hash=NULL WHERE status IN ("approved","rejected")');

        // Старые автономные пакеты содержали открытые или доступные Edge данные доступа.
        $pdo->exec('UPDATE edge_commands SET status="cancelled" WHERE status="pending"');
        $activeMissions = $pdo->query('SELECT id FROM missions WHERE status NOT IN ("completed","cancelled","failed")')->fetchAll(PDO::FETCH_COLUMN);
        foreach ($activeMissions as $missionId) {
            $mission = mission_for_user((int)$missionId, $admin);
            create_command($mission, 'stage_mission', mission_package($mission), 86400);
        }

        $pdo->prepare('INSERT INTO schema_migrations (migration_id,applied_at) VALUES (?,NOW())')->execute(['secure-v0.5']);
        audit_log('system_upgraded', 'system', 'secure-v0.5', ['messages'=>$messages,'robots'=>array_keys($robotKeys)], (int)$admin['id']);
        $done = true;
    } catch (Throwable $e) {
        error_log('Upgrade error: ' . $e->getMessage());
        $error = $e->getMessage();
    }
}
render_header('Обновление secure-v0.5', $admin);
?>
<section class="card auth-card">
<h1>Обновление secure-v0.5</h1>
<?php if ($done): ?>
<div class="alert success">Обновление завершено. Удалите <code>upgrade.php</code>, <code>setup.php</code> и <code>diagnostic.php</code>.</div>
<?php if ($robotKeys): ?><div class="alert warning"><strong>Скопируйте ключи Orange Pi сейчас.</strong> После обновления страницы они не будут показаны.</div><?php foreach ($robotKeys as $robotId=>$key): ?><p><strong><?= h($robotId) ?></strong><br><code><?= h($key) ?></code></p><?php endforeach; ?><?php else: ?><p>Ключи роботов уже существовали. При необходимости смените их в разделе «Безопасность».</p><?php endif; ?>
<?php foreach ($messages as $message): ?><p><?= h($message) ?></p><?php endforeach; ?>
<p><a class="button primary" href="<?= h(base_url('/admin/security')) ?>">Открыть безопасность</a></p>
<?php else: ?>
<?php if ($error): ?><div class="alert danger"><?= h($error) ?></div><?php endif; ?>
<div class="alert warning">Сначала скачайте резервную копию базы и файлов. После обновления удалите старые локальные SQLite-базы Edge и Orange Pi: старые пакеты могли содержать открытые PIN/RFID.</div>
<form method="post"><input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>"><button class="button primary" type="submit">Применить secure-v0.5</button></form>
<?php endif; ?>
</section>
<?php render_footer();
