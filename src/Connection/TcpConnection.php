<?php

namespace localzet\ShadowSocks\Connection;

use localzet\Server\Connection\AsyncTcpConnection;
use localzet\ShadowSocks\Encryptor;
use Protocol\ShadowsocksProtocol;
use Throwable;

/**
 *
 */
class TcpConnection
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
     * @var string
     */
    protected string $protocol;

    /**
     * @var array
     */
    protected array $protocol_param;

    /**
     * @param $user
     */
    public function __construct($user)
    {
        $this->method = $user['method'] ?? 'chacha20-ietf-poly1305';
        $this->password = $user['password'];
        $this->protocol = $user['protocol'] ?? '';
        $this->protocol_param = $user['protocol_param'] ?? [];
    }

    /**
     * @param mixed $internal
     * @return void
     */
    public function onConnect(mixed $internal): void
    {
        $internal->stage = STAGE_INIT;
        $internal->encryptor = new Encryptor($this->password, $this->method);
    }

    /**
     * @throws Throwable
     */
    public function onMessage(mixed $internal, mixed $buffer): null
    {
        // Если соединение находится на начальной стадии или стадии адреса
        if ($internal->stage == STAGE_INIT || $internal->stage == STAGE_ADDR) {

            // Расшифровываем полученные данные
            $buffer = $internal->encryptor->decrypt($buffer);

            // Получаем вектор инициализации и ключ
            $iv = $internal->encryptor->getIV(false);
            $key = $internal->encryptor->getKey();

            // Инициализируем класс протокола
            $internal->ssprotocol = new ShadowsocksProtocol($key, $iv, $this->protocol, $this->protocol_param);

            // Расшифровываем данные после получения от сервера
            $buffer = $internal->ssprotocol->ServerPostDecrypt($buffer);

            // Если произошла ошибка при расшифровке данных, закрываем соединение
            if ($buffer === false) {
                $internal->close();
                return null;
            }

            // Анализируем заголовок socket5
            $header_data = parse_socket5_header($buffer);

            // Если произошла ошибка при анализе заголовка, закрываем соединение
            if (!$header_data) {
                $internal->close();
                return null;
            }

            // Получаем длину заголовка
            $header_len = $header_data[3];

            // Анализируем и получаем реальный адрес и порт запроса
            $host = $header_data[1];
            $port = $header_data[2];

            // Формируем адрес для подключения
            $address = "tcp://$host:$port";

            // Если хост или порт пусты, закрываем соединение
            if (empty($host) || empty($port)) {
                $internal->close();
                return null;
            }

            // Создаем новое удаленное соединение
            $external = new AsyncTcpConnection($address);

            // Сохраняем ссылки на противоположные соединения
            $internal->external = $external;
            $external->internal = $internal;

            // Контроль потока: если буфер отправки удаленного соединения заполнен, останавливаем чтение данных от клиента shadowsocks
            $external->onBufferFull = function ($external) {
                $external->internal->pauseRecv();
            };

            // Контроль потока: если буфер отправки удаленного соединения опустошен, возобновляем чтение данных от клиента shadowsocks
            $external->onBufferDrain = function ($external) {
                $external->internal->resumeRecv();
            };

            // При получении сообщения от удаленного соединения, шифруем его и отправляем клиенту shadowsocks, который в свою очередь расшифрует его и отправляет браузеру
            $external->onMessage = function ($external, $buffer) {
                $buffer = $external->internal->ssprotocol->ServerPreEncrypt($buffer);
                $buffer = $external->internal->encryptor->encrypt($buffer);
                $external->internal->send($buffer);
            };

            // При закрытии удаленного соединения, закрываем соединение с клиентом shadowsocks
            $external->onClose = function ($external) {
                // Закрываем противоположное соединение
                $external->internal->close();
                $external->internal = null;
            };

            // При возникновении ошибки в удаленном соединении (обычно это ошибка при установке соединения), закрываем соединение с клиентом shadowsocks
            $external->onError = function ($external, $code, $msg) use ($address) {
                echo "Ошибка в удаленном соединении $address. Код ошибки: $code. Сообщение: $msg\n";
                $external->close();
                if (!empty($external->internal)) {
                    $external->internal->close();
                }
            };

            // Контроль потока: если буфер отправки клиента shadowsocks заполнен, останавливаем чтение данных от удаленного сервера
            $internal->onBufferFull = function ($internal) {
                $internal->external->pauseRecv();
            };

            // Контроль потока: если буфер отправки клиента shadowsocks опустошен, возобновляем чтение данных от удаленного сервера
            $internal->onBufferDrain = function ($internal) {
                $internal->external->resumeRecv();
            };

            // При получении сообщения от клиента shadowsocks, расшифровываем его и отправляем удаленному серверу
            $internal->onMessage = function ($internal, $buffer) {
                $buffer = $internal->encryptor->decrypt($buffer);
                $buffer = $internal->ssprotocol->ServerPostDecrypt($buffer);
                $internal->external->send($buffer);
            };

            // При закрытии соединения клиентом shadowsocks, закрываем соединение с удаленным сервером
            $internal->onClose = function ($internal) {
                $internal->external->close();
                $internal->external = null;
            };

            // При возникновении ошибки в соединении с клиентом shadowsocks, закрываем соединение с удаленным сервером
            $internal->onError = function ($internal, $code, $msg) {
                echo "Ошибка в соединении. Код ошибки: $code. Сообщение: $msg\n";
                $internal->close();
                if (isset($internal->external)) {
                    $internal->external->close();
                }
            };

            // Устанавливаем удаленное соединение
            $external->connect();

            // Меняем состояние текущего соединения на STAGE_STREAM, т.е. начинаем пересылку потока данных
            $internal->state = STAGE_STREAM;

            // Если первое сообщение от клиента shadowsocks превышает длину заголовка, отправляем оставшиеся данные удаленному серверу
            if (strlen($buffer) > $header_len) {
                $external->send(substr($buffer, $header_len));
            }
        }

        return null;
    }
}