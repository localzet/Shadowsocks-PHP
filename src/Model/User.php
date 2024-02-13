<?php

namespace localzet\ShadowSocks\Model;

use Exception;
use Triangle\MongoDB\Model;

/**
 * @property string $username
 * @property string|int $port
 * @property string $method
 * @property string $password
 */
class User extends Model
{
    public const STATUS_NONACTIVE = 0;
    public const STATUS_ACTIVE = 1;
    protected $table = 'Users';
    protected $guarded = [];
    protected $attributes = [
        'status' => self::STATUS_ACTIVE,
        'method' => 'chacha20-ietf-poly1305',
    ];
    protected static array $_methodSupported = [
        'none',
        'aes-128-cfb',
        'aes-192-cfb',
        'aes-256-cfb',
        'bf-cfb',
        'camellia-128-cfb',
        'camellia-192-cfb',
        'camellia-256-cfb',
        'cast5-cfb',
        'des-cfb',
        'idea-cfb',
        'rc2-cfb',
        'seed-cfb',
        'rc4',
        'rc4-md5',
        'rc4-md5-6',
        'aes-128-ctr',
        //gmp, OpenSSL
        'aes-192-ctr',
        //gmp, OpenSSL
        'aes-256-ctr',
        //gmp, OpenSSL
        'chacha20',
        //OpenSSL
        'chacha20-ietf',
        //OpenSSL
        'aes-128-gcm',
        //(PHP >= 7.1.0) OpenSSL
        'aes-192-gcm',
        //(PHP >= 7.1.0) OpenSSL
        'aes-256-gcm',
        //(PHP >= 7.1.0) OpenSSL or Sodium
        'chacha20-poly1305',
        //(PHP >= 7.2.0) Sodium
        'chacha20-ietf-poly1305',
        //(PHP >= 7.2.0) Sodium
        'xchacha20-ietf-poly1305',
        //(PHP >= 7.2.0) Sodium
    ];

    public function setMethod(string $method): bool
    {
        $method = strtolower($method);
        $exist = in_array($method, static::$_methodSupported);

        if ($exist) {
            return $this->update(['method' => $method]);
        }

        return false;
    }

    public function setPort(?int $port = null): bool
    {
        $exists = static::all()->pluck('port')->toArray();

        if ($port) {
            if (in_array($port, $exists)) {
                return false;
            }
        } else {
            $port = max($exists) + 1;
        }

        return $this->update(['port' => $port]);
    }

    public function setStatus(int $status): bool
    {
        return $this->update(['status' => $status]);
    }

    /**
     * @throws Exception
     */
    public static function register(string $username, string $password, ?int $port = null): bool
    {
        $exist = static::where('username', $username)->first();
        if ($exist) {
            throw new Exception("Пользователь с таким никнеймом уже существует");
        }

        return static::create(['username' => $username, 'password' => $password])?->setPort($port);
    }

    public static function allActive(): array
    {
        return static::where('status', self::STATUS_ACTIVE)->cursor()->toArray() ?? [];
    }
}