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
 * @return bool
 */
function is_phar(): bool
{
    return class_exists(Phar::class, false) && Phar::running();
}

/**
 * Анализирует данные заголовка socket5, отправленные клиентом shadowsocks
 * @param string $buffer Буфер для анализа
 * @return array|false Возвращает массив с данными заголовка или false в случае ошибки
 */
function parse_socket5_header(string $buffer): false|array
{
    /*
     * Заголовок TCP Relay Shadowsocks:
     *
     *    +------+----------+----------+
     *    | ATYP | DST.ADDR | DST.PORT |
     *    +------+----------+----------+
     *    |  1   | Variable |    2     |
     *    +------+----------+----------+
     *
     */

    if (strlen($buffer) < 1) {
        echo "Недопустимая длина для заголовка\n";
        return false;
    }

    $addr_type = ord($buffer[0]);
    switch ($addr_type) {
        case ADDRTYPE_IPV4:
            $header_length = 7;
            if (strlen($buffer) < $header_length) {
                echo "Недопустимая длина для ipv4 адреса\n";
                return false;
            }
            $dest_addr = ord($buffer[1]) . '.' . ord($buffer[2]) . '.' . ord($buffer[3]) . '.' . ord($buffer[4]);
            $port_data = unpack('n', substr($buffer, 5, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_HOST:
            if (strlen($buffer) < 2) {
                echo "Недопустимая длина имени хоста\n";
                return false;
            }
            $addrlen = ord($buffer[1]);
            $header_length = $addrlen + 4;
            if (strlen($buffer) < $header_length) {
                echo "Недопустимая длина имени хоста\n";
                return false;
            }
            $dest_addr = substr($buffer, 2, $addrlen);
            $port_data = unpack('n', substr($buffer, 2 + $addrlen, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_IPV6:
            // todo ...
            // ipv6 пока не поддерживается ...
            $header_length = 19;
            if (strlen($buffer) < $header_length) {
                echo "Недопустимая длина для ipv6 адреса\n";
                return false;
            }
            $dest_addr = inet_ntop(substr($buffer, 1, 16));
            $port_data = unpack('n', substr($buffer, 17, 2));
            $dest_port = $port_data[1];
            break;
        default:
            echo "Неподдерживаемый тип адреса $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

/**
 * Создает UDP-заголовок для ответа клиенту
 * @param string $addr Адрес
 * @param int $addr_type Тип адреса
 * @param int $port Порт
 * @return string|void Возвращает заголовок или ничего
 */
function pack_header($addr, $addr_type, $port)
{
    // Проверка, является ли адрес действительным общедоступным IPv4-адресом
    if(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
        $addr_type = ADDRTYPE_IPV4;
    }
    // Проверка, является ли адрес действительным IPv6-адресом
    elseif(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_RES_RANGE)){
        $addr_type = ADDRTYPE_IPV6;
    }

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
