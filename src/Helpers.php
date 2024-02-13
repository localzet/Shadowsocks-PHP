<?php

/**
 * @package     Triangle Engine (FrameX Project)
 * @link        https://github.com/localzet/FrameX      FrameX Project v1-2
 * @link        https://github.com/Triangle-org/Engine  Triangle Engine v2+
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2024 Localzet Group
 * @license     https://www.gnu.org/licenses/agpl AGPL-3.0 license
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as
 *              published by the Free Software Foundation, either version 3 of the
 *              License, or (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Events\Dispatcher;
use localzet\Server;
use localzet\ShadowSocks\Container;
use Monolog\Logger;
use Triangle\MongoDB\Connection as MongodbConnection;

/**
 *
 */
const STAGE_INIT = 0;
/**
 *
 */
const STAGE_ADDR = 1;
/**
 *
 */
const STAGE_UDP_ASSOC = 2;
/**
 *
 */
const STAGE_DNS = 3;
/**
 *
 */
const STAGE_CONNECTING = 4;
/**
 *
 */
const STAGE_STREAM = 5;
/**
 *
 */
const STAGE_DESTROYED = -1;

/**
 *
 */
const CMD_CONNECT = 1;
/**
 *
 */
const CMD_BIND = 2;
/**
 *
 */
const CMD_UDP_ASSOCIATE = 3;

/**
 *
 */
const ADDRTYPE_IPV4 = 1;
/**
 *
 */
const ADDRTYPE_IPV6 = 4;
/**
 *
 */
const ADDRTYPE_HOST = 3;

/**
 *
 */
define('BASE_PATH', dirname(__DIR__));

/**
 * @param array $connection
 * @return void
 */
function loadDatabase(array $connection): void
{
    $capsule = new Capsule(IlluminateContainer::getInstance());

    $capsule->getDatabaseManager()->extend('mongodb', function ($config, $name) {
        $config['name'] = $name;
        return new MongodbConnection($config);
    });

    $capsule->addConnection($connection);

    if (class_exists(Dispatcher::class) && !$capsule->getEventDispatcher()) {
        $capsule->setEventDispatcher(Container::make(Dispatcher::class, [IlluminateContainer::getInstance()]));
    }

    $capsule->setAsGlobal();
    $capsule->bootEloquent();
}

/**
 * return the program execute directory
 * @param string $path
 * @return string
 */
function run_path(string $path = ''): string
{
    static $runPath = '';
    if (!$runPath) {
        $runPath = is_phar() ? dirname(Phar::running(false)) : BASE_PATH;
    }
    return path_combine($runPath, $path);
}

/**
 * @param false|string $path
 * @return string
 */
function base_path(false|string $path = ''): string
{
    if (false === $path) {
        return run_path();
    }
    return path_combine(BASE_PATH, $path);
}

/**
 * @param string $path
 * @return string
 */
function runtime_path(string $path = ''): string
{
    return path_combine(run_path('ShadowSocksRuntime'), $path);
}

/**
 * Generate paths based on given information
 * @param string $front
 * @param string $back
 * @return string
 */
function path_combine(string $front, string $back): string
{
    return $front . ($back ? (DIRECTORY_SEPARATOR . ltrim($back, DIRECTORY_SEPARATOR)) : $back);
}

/**
 * @param $value
 * @param int $flags
 * @return string|false
 */
function json($value, int $flags = JSON_NUMERIC_CHECK | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR): false|string
{
    return json_encode($value, $flags);
}

/**
 * @param string $name
 * @return Logger
 */
function logger(string $name = 'default'): Logger
{
    $RotatingFileHandler = new Monolog\Handler\RotatingFileHandler(runtime_path('Log') . "/general.log", 7, Monolog\Logger::DEBUG);
    $LineFormatter = new Monolog\Formatter\LineFormatter(null, 'Y-m-d H:i:s', true);
    $RotatingFileHandler->setFormatter($LineFormatter);

    $MongoDBHandler = new Monolog\Handler\MongoDBHandler(new MongoDB\Client('mongodb://gen_user:lvanZ2003@db.localzet.com:27017'), 'ShadowSocks', 'Log_' . $name);
    $MongoDBFormatter = new Monolog\Formatter\MongoDBFormatter(10, false);
    $MongoDBHandler->setFormatter($MongoDBFormatter);

    $handlers = [
        $RotatingFileHandler,
        $MongoDBHandler,
    ];

    return new Logger($name, $handlers);
}

/**
 * Copy dir
 * @param string $source
 * @param string $dest
 * @param bool $overwrite
 * @return void
 */
function copy_dir(string $source, string $dest, bool $overwrite = false): void
{
    if (is_dir($source)) {
        if (!is_dir($dest)) {
            mkdir($dest);
        }
        $files = scandir($source);
        foreach ($files as $file) {
            if ($file !== "." && $file !== "..") {
                copy_dir("$source/$file", "$dest/$file");
            }
        }
    } else if (file_exists($source) && ($overwrite || !file_exists($dest))) {
        copy($source, $dest);
    }
}

/**
 * Remove dir
 * @param string $dir
 * @return bool
 */
function remove_dir(string $dir): bool
{
    if (is_link($dir) || is_file($dir)) {
        return unlink($dir);
    }
    $files = array_diff(scandir($dir), array('.', '..'));
    foreach ($files as $file) {
        (is_dir("$dir/$file") && !is_link($dir)) ? remove_dir("$dir/$file") : unlink("$dir/$file");
    }
    return rmdir($dir);
}

/**
 * @param $server
 * @param $class
 */
function server_bind($server, $class): void
{
    $callbackMap = [
        'onConnect',
        'onMessage',
        'onClose',
        'onError',
        'onBufferFull',
        'onBufferDrain',
        'onServerStop',
        'onWebSocketConnect',
        'onServerReload'
    ];
    foreach ($callbackMap as $name) {
        if (method_exists($class, $name)) {
            $server->$name = [$class, $name];
        }
    }
    if (method_exists($class, 'onServerStart')) {
        call_user_func([$class, 'onServerStart'], $server);
    }
}

/**
 * @param $config
 * @return Server
 */
function server_start($config): Server
{
    $server = new Server($config['listen'] ?? null, $config['context'] ?? []);
    $propertyMap = [
        'name',
        'count',
        'user',
        'group',
        'reloadable',
        'reusePort',
        'transport',
        'protocol',
    ];
    foreach ($propertyMap as $property) {
        if (isset($config[$property])) {
            $server->$property = $config[$property];
        }
    }

    $server->onServerStart = function ($server) use ($config) {
        set_error_handler(
            function ($level, $message, $file = '', $line = 0) {
                if (error_reporting() & $level) {
                    throw new ErrorException($message, 0, $level, $file, $line);
                }
            }
        );

        register_shutdown_function(
            function ($start_time) {
                if (time() - $start_time <= 1) {
                    sleep(1);
                }
            },
            time()
        );

        if (isset($config['handler'])) {
            if (!class_exists($config['handler'])) {
                echo "process error: class {$config['handler']} not exists\r\n";
                return;
            }

            $instance = Container::make($config['handler'], $config['constructor'] ?? []);
            server_bind($server, $instance);
        }
    };

    return $server;
}


/**
 * @return bool
 */
function is_phar(): bool
{
    return class_exists(Phar::class, false) && Phar::running();
}

/**
 * @return int
 */
function cpu_count(): int
{
    // Винда опять не поддерживает это
    if (DIRECTORY_SEPARATOR === '\\') {
        return 1;
    }
    $count = 4;
    if (is_callable('shell_exec')) {
        if (strtolower(PHP_OS) === 'darwin') {
            $count = (int)shell_exec('sysctl -n machdep.cpu.core_count');
        } else {
            $count = (int)shell_exec('nproc');
        }
    }
    return $count > 0 ? $count : 4;
}

/**
 * Валидация IP-адреса
 *
 * @param string $ip IP-адрес
 *
 * @return boolean
 */
function validateIp(string $ip): bool
{
    if (strtolower($ip) === 'unknown')
        return false;
    $ip = ip2long($ip);
    if ($ip !== false && $ip !== -1) {
        $ip = sprintf('%u', $ip);
        if ($ip >= 0 && $ip <= 50331647)
            return false;
        if ($ip >= 167772160 && $ip <= 184549375)
            return false;
        if ($ip >= 2130706432 && $ip <= 2147483647)
            return false;
        if ($ip >= 2851995648 && $ip <= 2852061183)
            return false;
        if ($ip >= 2886729728 && $ip <= 2887778303)
            return false;
        if ($ip >= 3221225984 && $ip <= 3221226239)
            return false;
        if ($ip >= 3232235520 && $ip <= 3232301055)
            return false;
        if ($ip >= 4294967040)
            return false;
    }
    return true;
}

/**
 * @param string $ip
 * @return bool
 */
function isIntranetIp(string $ip): bool
{
    // Не IP.
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    // Точно ip Интранета? Для IPv4 FALSE может быть не точным, поэтому нам нужно проверить его вручную ниже.
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
    }
    // Ручная проверка IPv4.
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    // Ручная проверка
    // $reservedIps = [
    //     '167772160'  => 184549375,  // 10.0.0.0 -  10.255.255.255
    //     '3232235520' => 3232301055, // 192.168.0.0 - 192.168.255.255
    //     '2130706432' => 2147483647, // 127.0.0.0 - 127.255.255.255
    //     '2886729728' => 2887778303, // 172.16.0.0 -  172.31.255.255
    // ];
    $reservedIps = [
        1681915904 => 1686110207,   // 100.64.0.0 -  100.127.255.255
        3221225472 => 3221225727,   // 192.0.0.0 - 192.0.0.255
        3221225984 => 3221226239,   // 192.0.2.0 - 192.0.2.255
        3227017984 => 3227018239,   // 192.88.99.0 - 192.88.99.255
        3323068416 => 3323199487,   // 198.18.0.0 - 198.19.255.255
        3325256704 => 3325256959,   // 198.51.100.0 - 198.51.100.255
        3405803776 => 3405804031,   // 203.0.113.0 - 203.0.113.255
        3758096384 => 4026531839,   // 224.0.0.0 - 239.255.255.255
    ];

    $ipLong = ip2long($ip);

    foreach ($reservedIps as $ipStart => $ipEnd) {
        if (($ipLong >= $ipStart) && ($ipLong <= $ipEnd)) {
            return true;
        }
    }
    return false;
}

/**
 * Генерация ID
 *
 * @return string
 */
function generateId(): string
{
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff)
    );
}

/**
 * 解析shadowsocks客户端发来的socket5头部数据
 * @param string $buffer
 * @return array|false
 */
function parse_socket5_header(string $buffer): false|array
{
    /*
     * Shadowsocks TCP Relay Header:
     *
     *    +------+----------+----------+
     *    | ATYP | DST.ADDR | DST.PORT |
     *    +------+----------+----------+
     *    |  1   | Variable |    2     |
     *    +------+----------+----------+
     *
     */
    //检查长度
    if (strlen($buffer) < 1) {
        echo "invalid length for header\n";
        return false;
    }
    $addr_type = ord($buffer[0]);
    switch ($addr_type) {
        case ADDRTYPE_IPV4:
            $header_length = 7;
            if (strlen($buffer) < $header_length) {
                echo "invalid length for ipv4 address\n";
                return false;
            }
            $dest_addr = ord($buffer[1]) . '.' . ord($buffer[2]) . '.' . ord($buffer[3]) . '.' . ord($buffer[4]);
            $port_data = unpack('n', substr($buffer, 5, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_HOST:
            if (strlen($buffer) < 2) {
                echo "invalid length host name length\n";
                return false;
            }
            $addrlen = ord($buffer[1]);
            $header_length = $addrlen + 4;
            if (strlen($buffer) < $header_length) {
                echo "invalid host name length\n";
                return false;
            }
            $dest_addr = substr($buffer, 2, $addrlen);
            $port_data = unpack('n', substr($buffer, 2 + $addrlen, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_IPV6:
            // todo ...
            // ipv6 not support yet ...
            $header_length = 19;
            if (strlen($buffer) < $header_length) {
                echo "invalid length for ipv6 address\n";
                return false;
            }
            $dest_addr = inet_ntop(substr($buffer, 1, 16));
            $port_data = unpack('n', substr($buffer, 17, 2));
            $dest_port = $port_data[1];
            break;
        default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

/*
 UDP 部分 返回客户端 头部数据 by @Zac
 //生成UDP header 它这里给返回解析出来的域名貌似给udp dns域名解析用的
*/
/**
 * @param $addr
 * @param $addr_type
 * @param $port
 * @return string|void
 */
function pack_header($addr, $addr_type, $port)
{
    $header = '';
    //$ip = pack('N',ip2long($addr));
    //判断是否是合法的公共IPv4地址，192.168.1.1这类的私有IP地址将会排除在外
    /*
     if(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
     // it's valid
     $addr_type = ADDRTYPE_IPV4;
     //判断是否是合法的IPv6地址
     }elseif(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)){
     $addr_type = ADDRTYPE_IPV6;
     }
     */
    switch ($addr_type) {
        case ADDRTYPE_IPV4:
            $header = b"\x01" . inet_pton($addr);
            break;
        case ADDRTYPE_IPV6:
            $header = b"\x04" . inet_pton($addr);
            break;
        case ADDRTYPE_HOST:
            if (strlen($addr) > 255) {
                $addr = substr($addr, 0, 255);
            }
            $header = b"\x03" . chr(strlen($addr)) . $addr;
            break;
        default:
            return;
    }
    return $header . pack('n', $port);
}
