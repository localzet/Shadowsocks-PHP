<?php

namespace localzet\ShadowSocks\App;

use localzet\Server\Connection\AsyncUdpConnection;
use localzet\ShadowSocks\Encryptor;
use Throwable;

/**
 *
 */
class UDP
{
    /**
     * @var string
     */
    protected string $method;

    /**
     * @var string
     */
    protected string $password;

    /**
     * @param $user
     */
    public function __construct($user)
    {
        $this->method = $user['method'] ?? 'chacha20-ietf-poly1305';
        $this->password = $user['password'];
    }

    /**
     * @throws Throwable
     */
    public function onMessage(mixed $internal, mixed $buffer): null
    {
        // Создаем новый экземпляр класса Encryptor с заданным паролем и методом шифрования
        $internal->encryptor = new Encryptor($this->password, $this->method, true);

        // Расшифровываем полученные данные
        $buffer = $internal->encryptor->decrypt($buffer);

        // Анализируем заголовок socket5
        $header_data = parse_socket5_header($buffer);

        // Если анализ заголовка не удался, закрываем соединение
        if (!$header_data) {
            $internal->close();
            return null;
        }

        // Длина заголовка
        $header_len = $header_data[3];

        // Хост и порт для подключения
        $host = $header_data[1];
        $port = $header_data[2];

        // Формируем адрес для подключения
        $address = "udp://$host:$port";

        // Создаем новое удаленное соединение
        $external = new AsyncUdpConnection($address);

        // Сохраняем ссылки на противоположные соединения
        $internal->external = $external;
        $external->internal = $internal;

        // При успешном подключении отправляем данные, начиная с конца заголовка
        $external->onConnect = function ($external) use ($buffer, $header_len) {
            $external->send(substr($buffer, $header_len));
        };

        // При получении сообщения шифруем его и отправляем обратно
        $external->onMessage = function ($external, $buffer) use ($header_data) {
            $_header = pack_header($header_data[1], $header_data[0], $header_data[2]);
            $buffer = $external->internal->encryptor->encrypt($_header . $buffer);
            $external->internal->send($buffer);
        };

        // Подключаемся к удаленному серверу
        $external->connect();

        return null;
    }
}