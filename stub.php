<?php

use localzet\Server;
use localzet\ShadowSocks\App\TCP;
use localzet\ShadowSocks\App\UDP;
use localzet\ShadowSocks\Model\User;
use MongoDB\Driver\Exception\ConnectionTimeoutException;

const IN_PHAR = true;
Phar::mapPhar('ShadowSocks');

require_once 'phar://ShadowSocks/vendor/autoload.php';

try {
    error_reporting(E_ALL);
    ini_set('display_errors', 'on');
    date_default_timezone_set("Europe/Moscow");

    loadDatabase([
        'driver' => 'mongodb',
        'host' => 'db.localzet.com',
        'port' => 27017,
        'database' => 'ShadowSocks',
        'username' => 'gen_user',
        'password' => 'lvanZ2003',
        'options' => [
            'authSource' => 'admin',
            'appname' => 'Triangle VPN',
            'directConnection' => 'true'
        ],
    ]);

    $users = User::allActive();

    if (empty($users)) {
        User::register('test', '12345678', 4433);
        User::register('test2', '12345678', 20001);
    }

    /** @var User $user */
    foreach (User::allActive() as $user) {
        // TCP-Server
        server_start([
            'name' => ($user['username'] ? $user['username'] . ' TCP' : 'ShadowSocks TCP'),
            'count' => cpu_count() * 4,

            'reloadable' => false,
            'reusePort' => true,

            'listen' => 'tcp://0.0.0.0:' . $user['port'],

            'handler' => TCP::class,
            'constructor' => [$user],
        ]);

        // UDP-Server
        server_start([
            'name' => ($user['username'] ? $user['username'] . ' UDP' : 'ShadowSocks UDP'),
            'count' => 1,

            'reloadable' => false,
            'reusePort' => true,

            'listen' => 'udp://0.0.0.0:' . $user['port'],

            'handler' => UDP::class,
            'constructor' => [$user],
        ]);
    }

    Server::$logFile = runtime_path() . "/master.log";
    Server::$pidFile = runtime_path() . "/master.pid";
    Server::$statusFile = runtime_path() . "/master.status";
    Server::$stdoutFile = runtime_path() . "/master.stdout";
    Server::$onMasterReload = function () {
        Server::log('$onMasterReload');
        if (function_exists('opcache_get_status')) {
            if ($status = opcache_get_status()) {
                if (isset($status['scripts']) && $scripts = $status['scripts']) {
                    foreach (array_keys($scripts) as $file) {
                        opcache_invalidate($file, true);
                    }
                }
            }
        }
    };

    Server::runAll();
} catch (ConnectionTimeoutException $e) {
    Server::log("База данных недоступна");
}
__HALT_COMPILER();

?>