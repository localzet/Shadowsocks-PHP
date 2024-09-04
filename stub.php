<?php

use localzet\Server;
use localzet\ShadowSocks\Connection\TcpConnection;
use localzet\ShadowSocks\Connection\UdpConnection;
use localzet\ShadowSocks\Model\User;
use MongoDB\Driver\Exception\ConnectionTimeoutException;

const IN_PHAR = true;
Phar::mapPhar('ShadowSocks');

require_once 'phar://ShadowSocks/vendor/autoload.php';

try {
    ini_set('display_errors', 'on');
    error_reporting(E_ALL);
    date_default_timezone_set("Europe/Moscow");

    $runtimeLogsPath = runtime_path('logs');
    if (!file_exists($runtimeLogsPath) || !is_dir($runtimeLogsPath)) {
        if (!mkdir($runtimeLogsPath, 0777, true)) {
            throw new RuntimeException("Failed to create runtime logs directory. Please check the permission.");
        }
    }

    Server::$onMasterReload = function () {
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

    Server::$logFile = runtime_path() . "/master.log";
    Server::$pidFile = runtime_path() . "/master.pid";
    Server::$statusFile = runtime_path() . "/master.status";
    Server::$stdoutFile = runtime_path() . "/master.stdout";
    Server::$stopTimeout = 2;
    Server\Connection\TcpConnection::$defaultMaxPackageSize = 10 * 1024 * 1024;

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
        localzet_start(
            name: $user['username'] ? $user['username'] . ' TCP' : 'ShadowSocks TCP',
            count: cpu_count() * 4,
            listen: 'tcp://0.0.0.0:' . $user['port'],
            reloadable: false,
            reusePort: true,
            handler: TcpConnection::class,
            constructor: [$user],
            onServerStart: function (?Server $server) {
                set_error_handler(fn($level, $message, $file = '', $line = 0) => (error_reporting() & $level) ? throw new ErrorException($message, 0, $level, $file, $line) : true);
                register_shutdown_function(fn($start_time) => (time() - $start_time <= 1) ? sleep(1) : true, time());
            }
        );

        // UDP-Server
        localzet_start(
            name: $user['username'] ? $user['username'] . ' UDP' : 'ShadowSocks UDP',
            listen: 'udp://0.0.0.0:' . $user['port'],
            reloadable: false,
            reusePort: true,
            transport: 'udp',
            handler: UdpConnection::class,
            constructor: [$user],
            onServerStart: function (?Server $server) {
                set_error_handler(fn($level, $message, $file = '', $line = 0) => (error_reporting() & $level) ? throw new ErrorException($message, 0, $level, $file, $line) : true);
                register_shutdown_function(fn($start_time) => (time() - $start_time <= 1) ? sleep(1) : true, time());
            }
        );
    }

    if (!defined('GLOBAL_START')) {
        Server::runAll();
    }
} catch (ConnectionTimeoutException $e) {
    Server::log("База данных недоступна");
}
__HALT_COMPILER();

?>