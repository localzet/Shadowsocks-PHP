<?php

require_once __DIR__ . '/vendor/autoload.php';

$path = __DIR__;
$name = "ShadowSocks";
$exclude = [
    '.env', 'LICENSE',
    'composer.json', 'composer.lock',
    'ShadowSocks.phar', 'ShadowSocks.php',
    'phar.php', 'stub.php'
];

remove_dir($path . '/ShadowSocksRuntime');

try {
    if (!class_exists(Phar::class, false)) {
        throw new RuntimeException("Не установлено расширение Phar!");
    }

    if (ini_get('phar.readonly')) {
        throw new RuntimeException("Включён параметр 'phar.readonly', поставь его в 'Off' или выполни 'php -d phar.readonly=0 " . __FILE__ . "'");
    }

    $phar_file = $path . '/' . $name . '.phar';

    if (file_exists($phar_file)) {
        unlink($phar_file);
    }

    if (file_exists($phar_file . '.gz')) {
        unlink($phar_file . '.gz');
    }

    echo("Сбор файлов в $phar_file\n");

    $phar = new Phar($phar_file, 0, $name);

    $phar->startBuffering();

    $phar->setSignatureAlgorithm(Phar::SHA256);

    $phar->buildFromDirectory($path);

    $exclude_files = $exclude + [$name . '.phar'];

    foreach ($exclude_files as $file) {
        if ($phar->offsetExists($file)) {
            $phar->delete($file);
        }
    }

    echo("Сбор файлов завершен, начинаю добавлять файлы в Phar\n");

    $phar->setStub("#!/usr/bin/env php
" . file_get_contents(__DIR__ . '/stub.php'));

    echo("Запись запросов в Phar архив и сохранение изменений\n");

    $phar->stopBuffering();

    chmod($phar_file, 0770);

} catch (Exception $e) {
    echo $e->getMessage() . "\n";
}