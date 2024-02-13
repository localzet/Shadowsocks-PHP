<?php

namespace localzet\ShadowSocks;

use localzet\ShadowSocks\Cipher\AEAD\AEADDecipher;
use localzet\ShadowSocks\Cipher\AEAD\AEADEncipher;
use localzet\ShadowSocks\Cipher\CFB\CfbDecipher;
use localzet\ShadowSocks\Cipher\CFB\CfbEncipher;
use localzet\ShadowSocks\Cipher\CipherInterface;
use localzet\ShadowSocks\Cipher\CTREncipher;
use localzet\ShadowSocks\Cipher\NoneEncipher;
use localzet\ShadowSocks\Cipher\RC4Encipher;
use SodiumException;

/**
 * @author walkor <walkor@workerman.net>
 * @author Ivan Zorin <creator@localzet.com>
 */
class Encryptor
{
    /**
     * @var
     */
    protected $_password;
    /**
     * @var string
     */
    protected string $_key;
    /**
     * @var string
     */
    protected string $_method;
    /**
     * @var ?CipherInterface
     */
    protected ?CipherInterface $_cipher = null;
    /**
     * @var ?CipherInterface
     */
    protected ?CipherInterface $_decipher = null;
    /**
     * @var array
     */
    protected array $_bytesToKeyResults = array();
    /**
     * @var
     */
    protected $_send_iv;
    /**
     * @var
     */
    protected $_recv_iv;
    /**
     * @var false
     */
    protected bool $_ivSent;
    /**
     * @var false|mixed
     */
    protected mixed $_onceMode;
    /**
     * @var int[][]
     */
    protected static array $_methodSupported = array(
        'none' => array(16, 0),
        'aes-128-cfb' => array(16, 16),
        'aes-192-cfb' => array(24, 16),
        'aes-256-cfb' => array(32, 16),
        'bf-cfb' => array(16, 8),
        'camellia-128-cfb' => array(16, 16),
        'camellia-192-cfb' => array(24, 16),
        'camellia-256-cfb' => array(32, 16),
        'cast5-cfb' => array(16, 8),
        'des-cfb' => array(8, 8),
        'idea-cfb' => array(16, 8),
        'rc2-cfb' => array(16, 8),
        'seed-cfb' => array(16, 16),
        'rc4' => array(16, 0),
        'rc4-md5' => array(16, 16),
        'rc4-md5-6' => array(16, 6),
        'aes-128-ctr' => array(16, 16),
        //gmp, OpenSSL
        'aes-192-ctr' => array(24, 16),
        //gmp, OpenSSL
        'aes-256-ctr' => array(32, 16),
        //gmp, OpenSSL
        'chacha20' => array(32, 8),
        //OpenSSL
        'chacha20-ietf' => array(32, 12),
        //OpenSSL
        'aes-128-gcm' => array(16, 16),
        //(PHP >= 7.1.0) OpenSSL 对于AEAD，第二个参数是salt长度
        'aes-192-gcm' => array(24, 24),
        //(PHP >= 7.1.0) OpenSSL
        'aes-256-gcm' => array(32, 32),
        //(PHP >= 7.1.0) OpenSSL or Sodium
        'chacha20-poly1305' => array(32, 32),
        //(PHP >= 7.2.0) Sodium
        'chacha20-ietf-poly1305' => array(32, 32),
        //(PHP >= 7.2.0) Sodium
        'xchacha20-ietf-poly1305' => array(32, 32),
        //(PHP >= 7.2.0) Sodium
    );

    /**
     * @var
     */
    protected $bytesToKeyResults;

    /**
     * @param $key
     * @param $method
     * @param bool $onceMode
     */
    public function __construct($key, $method, bool $onceMode = false)
    {
        $this->_password = $key;
        $this->_method = strtolower($method);
        $this->_ivSent = false;
        $this->_onceMode = $onceMode;
        $iv_len = $this->getCipherLen($this->_method);
        $iv_len = $iv_len[1];
        $iv = $iv_len ? openssl_random_pseudo_bytes($iv_len) : null;
        $this->_cipher = $this->getCipher($this->_password, $this->_method, 1, $iv);
    }

    /**
     * Функция getCipher создает экземпляр шифра на основе переданных параметров.
     *
     * @param string $password Пароль для генерации ключа шифрования.
     * @param string $method Метод шифрования.
     * @param int $op Операция шифрования (1 для шифрования, 0 для дешифрования).
     * @param string $iv Вектор инициализации.
     * @return CipherInterface|void Возвращает экземпляр класса шифра.
     */
    protected function getCipher(
        string $password,
        string $method,
        int    $op,
        string $iv
    )
    {
        // Получаем длину ключа и IV для выбранного метода шифрования
        $m = $this->getCipherLen($method);

        if ($m) {
            // Генерируем ключ и IV с использованием пароля и длин из предыдущего шага
            $ref = $this->EVPBytesToKey($password, $m[0], $m[1]);

            // Сохраняем сгенерированный ключ
            $this->_key = $key = $ref[0];

            // Получаем IV
            $iv_ = $ref[1];

            // Если IV не был передан, используем сгенерированный
            if ($iv == null) {
                $iv = $iv_;
            }

            // Обрезаем IV до нужной длины
            $iv = substr($iv, 0, $m[1]);

            // Если операция - шифрование, сохраняем IV для отправки
            if ($op === 1) {
                $this->_send_iv = $iv;
            } else {
                // Иначе сохраняем IV для приема
                $this->_recv_iv = $iv;
            }

            // В зависимости от выбранного метода создаем экземпляр соответствующего класса шифра
            switch ($method) {
                case 'none':
                    return new NoneEncipher();
                case 'rc4':
                    return new RC4Encipher($key);
                case 'rc4-md5':
                case 'rc4-md5-6':
                    // Для RC4-MD5 генерируем ключ путем конкатенации ключа и IV и вычисления MD5 хеша
                    $rc4_key = md5($key . $iv, true);
                    return new RC4Encipher($rc4_key);
                case 'aes-128-gcm':
                case 'aes-192-gcm':
                case 'aes-256-gcm':
                case 'chacha20-poly1305':
                case 'chacha20-ietf-poly1305':
                case 'xchacha20-ietf-poly1305':
                    // Для AEAD шифров используем IV в качестве соли
                    $salt = $iv;
                    if ($op === 1) {
                        // Если операция - шифрование, создаем экземпляр AEADEncipher
                        return new AEADEncipher($method, $key, $salt, $this->_onceMode);
                    } else {
                        // Иначе создаем экземпляр AEADDecipher
                        return new AEADDecipher($method, $key, $salt, $this->_onceMode);
                    }
                case 'aes-128-ctr':
                case 'aes-192-ctr':
                case 'aes-256-ctr':
                case 'chacha20':
                case 'chacha20-ietf':
                    // Для CTR шифров создаем экземпляр CTREncipher
                    return new CTREncipher($method, $key, $iv);
                default:
                    if ($op === 1) {
                        // Если операция - шифрование, создаем экземпляр CfbEncipher
                        return new CfbEncipher($method, $key, $iv);
                    } else {
                        // Иначе создаем экземпляр CfbDecipher
                        return new CfbDecipher($method, $key, $iv);
                    }
            }
        }
    }


    /**
     * Функция getKey возвращает ключ шифрования.
     *
     * @return string Возвращает ключ шифрования.
     */
    public function getKey(): string
    {
        return $this->_key;
    }

    /**
     * Функция getIV возвращает вектор инициализации.
     *
     * @param bool $send Если true, возвращает вектор инициализации для отправки, иначе для приема.
     * @return string Возвращает вектор инициализации.
     */
    public function getIV(bool $send = false): string
    {
        if ($send)
            return $this->_send_iv;
        else
            return $this->_recv_iv;
    }

    /**
     * Функция encrypt шифрует переданный буфер.
     *
     * @param string $buffer Буфер для шифрования.
     * @return string Возвращает зашифрованный буфер.
     * @throws SodiumException
     * @throws SodiumException
     */
    public function encrypt(string $buffer): string
    {
        // Обновляем состояние шифра с переданным буфером
        $result = $this->_cipher->update($buffer);

        // Если IV уже был отправлен, просто возвращаем результат
        if ($this->_ivSent) {
            return $result;
        } else {
            // Иначе добавляем IV к результату и отмечаем, что IV был отправлен
            $this->_ivSent = true;
            return $this->_send_iv . $result;
        }
    }

    /**
     * Функция decrypt дешифрует переданный буфер.
     *
     * @param string $buffer Буфер для дешифрования.
     * @return string Возвращает дешифрованный буфер.
     * @throws SodiumException
     * @throws SodiumException
     */
    public function decrypt(string $buffer): string
    {
        // Если дешифратор еще не был создан
        if (!$this->_decipher) {
            // Получаем длину IV для текущего метода
            $decipher_iv_len = $this->getCipherLen($this->_method);
            $decipher_iv_len = $decipher_iv_len[1];

            // Извлекаем IV из буфера
            $decipher_iv = substr($buffer, 0, $decipher_iv_len);

            // Создаем дешифратор с извлеченным IV
            $this->_decipher = $this->getCipher($this->_password, $this->_method, 0, $decipher_iv);

            // Обновляем состояние дешифратора с оставшейся частью буфера и возвращаем результат
            return $this->_decipher->update(substr($buffer, $decipher_iv_len));
        } else {
            // Если дешифратор уже был создан, просто обновляем его состояние с буфером и возвращаем результат
            return $this->_decipher->update($buffer);
        }
    }

    /**
     * Функция EVPBytesToKey генерирует ключ и вектор инициализации на основе пароля.
     *
     * @param string $password Пароль для генерации ключа и IV.
     * @param int $key_len Длина ключа.
     * @param int $iv_len Длина IV.
     * @return array Возвращает массив с ключом и IV.
     */
    protected function EVPBytesToKey(string $password, int $key_len, int $iv_len): array
    {
        // Создаем ключ кэша из пароля, длины ключа и длины IV
        $cache_key = "$password:$key_len:$iv_len";

        // Если результат уже был рассчитан ранее, возвращаем его
        if (isset($this->_bytesToKeyResults[$cache_key])) {
            return $this->_bytesToKeyResults[$cache_key];
        }

        // Инициализируем переменные
        $m = array();
        $i = 0;
        $count = 0;

        // Генерируем достаточное количество данных для создания ключа и IV
        while ($count < $key_len + $iv_len) {
            // Если это не первый цикл, добавляем предыдущие данные к паролю
            $data = $password;
            if ($i > 0) {
                $data = $m[$i - 1] . $password;
            }

            // Вычисляем MD5 хеш от данных
            $d = md5($data, true);

            // Добавляем хеш в массив
            $m[] = $d;

            // Увеличиваем счетчик на длину хеша
            $count += strlen($d);

            // Увеличиваем индекс
            $i += 1;
        }
        // Объединяем все хеши в одну строку
        $ms = implode('', $m);

        // Получаем ключ и IV из строки
        $key = substr($ms, 0, $key_len);
        $iv = substr($ms, $key_len, $key_len + $iv_len);

        // Сохраняем результат в кэше
        $this->bytesToKeyResults[$password] = array($key, $iv);

        // Возвращаем ключ и IV
        return array($key, $iv);
    }

    /**
     * Функция getCipherLen возвращает длину ключа и IV для выбранного метода шифрования.
     *
     * @param string $method Метод шифрования.
     * @return array|null Возвращает массив с длиной ключа и IV или null, если метод не поддерживается.
     */
    protected function getCipherLen(string $method): ?array
    {
        return self::$_methodSupported[$method] ?? null;
    }
}
