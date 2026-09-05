<?php
// Временная диагностика Beget. После проверки удалите этот файл.
header('Content-Type: text/html; charset=UTF-8');

function e($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$items = [
    'Время сервера' => date('c'),
    'PHP версия' => PHP_VERSION,
    'PHP SAPI' => PHP_SAPI,
    'ОС сервера' => PHP_OS,
    'Архитектура' => PHP_INT_SIZE * 8 . '-bit',
    'Сервер ПО' => $_SERVER['SERVER_SOFTWARE'] ?? 'не указано',
    'Имя хоста' => gethostname() ?: 'не указано',
    'Протокол' => $_SERVER['SERVER_PROTOCOL'] ?? 'не указано',
    'HTTPS' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'включён' : 'выключен',
    'Корень сайта' => $_SERVER['DOCUMENT_ROOT'] ?? 'не указано',
    'Память PHP' => ini_get('memory_limit'),
    'Макс. размер POST' => ini_get('post_max_size'),
    'Макс. размер загрузки' => ini_get('upload_max_filesize'),
    'Макс. время выполнения' => ini_get('max_execution_time') . ' сек.',
    'Часовой пояс PHP' => date_default_timezone_get(),
];

$extensions = get_loaded_extensions();
sort($extensions, SORT_NATURAL | SORT_FLAG_CASE);
?>
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Диагностика сервера</title>
  <style>
    body{font:16px system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 16px;color:#222}
    table{border-collapse:collapse;width:100%;margin:16px 0 28px}td{border:1px solid #ccc;padding:9px;vertical-align:top}
    td:first-child{font-weight:600;width:35%;background:#f5f5f5}code{word-break:break-all}
    .warn{padding:12px;background:#fff3cd;border:1px solid #e0b84c;border-radius:6px}
  </style>
</head>
<body>
  <h1>Диагностика сервера</h1>
  <p class="warn">Временный файл. После проверки удалите <code>server-info.php</code> из хостинга.</p>
  <h2>Основные параметры</h2>
  <table><?php foreach ($items as $key => $value): ?><tr><td><?= e($key) ?></td><td><code><?= e($value) ?></code></td></tr><?php endforeach; ?></table>
  <h2>Расширения PHP (<?= count($extensions) ?>)</h2>
  <p><?= e(implode(', ', $extensions)) ?></p>
</body>
</html>
