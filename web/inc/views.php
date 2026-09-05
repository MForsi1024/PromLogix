<?php
declare(strict_types=1);

function render_header(string $title, ?array $user = null, string $active = ''): void
{
    $flashes = take_flashes();
    ?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title><?= h($title) ?> — PromLogix</title>
    <link rel="stylesheet" href="<?= h(base_url('/assets/app.css')) ?>">
</head>
<body>
<?php if ($user): ?>
<header class="topbar">
    <a class="brand" href="<?= h(base_url('/dashboard')) ?>"><img class="brand-logo" src="<?= h(base_url('/assets/promlogix.jpg')) ?>" alt=""><span>PromLogix</span></a>
    <nav class="nav">
        <a class="<?= $active === 'dashboard' ? 'active' : '' ?>" href="<?= h(base_url('/dashboard')) ?>">Панель</a>
        <a class="<?= $active === 'new' ? 'active' : '' ?>" href="<?= h(base_url('/missions/new')) ?>">Новый заказ</a>
        <?php if (is_admin($user)): ?>
            <a class="<?= $active === 'recipients' ? 'active' : '' ?>" href="<?= h(base_url('/recipients')) ?>">RFID</a>
            <a class="<?= $active === 'map' ? 'active' : '' ?>" href="<?= h(base_url('/admin/map')) ?>">Карта</a>
            <a class="<?= $active === 'requests' ? 'active' : '' ?>" href="<?= h(base_url('/admin/requests')) ?>">Заявки</a>
            <a class="<?= $active === 'users' ? 'active' : '' ?>" href="<?= h(base_url('/admin/users')) ?>">Пользователи</a>
            <a class="<?= $active === 'security' ? 'active' : '' ?>" href="<?= h(base_url('/admin/security')) ?>">Безопасность</a>
        <?php endif; ?>
    </nav>
    <div class="account">
        <span><?= h($user['full_name']) ?></span>
        <form method="post" action="<?= h(base_url('/logout')) ?>">
            <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
            <button class="link-button" type="submit">Выйти</button>
        </form>
    </div>
</header>
<?php endif; ?>
<main class="page <?= $user ? '' : 'page-auth' ?>">
    <?php foreach ($flashes as $flash): ?>
        <div class="alert <?= h($flash['type']) ?>"><?= h($flash['message']) ?></div>
    <?php endforeach; ?>
<?php
}

function render_footer(array $scripts = []): void
{
    ?>
</main>
<script src="<?= h(base_url('/assets/app.js')) ?>"></script>
<?php foreach ($scripts as $src): ?><script src="<?= h(base_url($src)) ?>"></script><?php endforeach; ?>
</body>
</html>
<?php
}

function page_title(string $title, string $subtitle = '', string $actionHtml = ''): void
{
    ?>
<div class="page-heading">
    <div><h1><?= h($title) ?></h1><?php if ($subtitle !== ''): ?><p><?= h($subtitle) ?></p><?php endif; ?></div>
    <?php if ($actionHtml !== ''): ?><div><?= $actionHtml ?></div><?php endif; ?>
</div>
<?php
}

function empty_state(string $title, string $text): void
{
    ?><section class="card empty"><h3><?= h($title) ?></h3><p><?= h($text) ?></p></section><?php
}
