<?php

namespace localzet\ShadowSocks\Cipher\AEAD;

class AbstractAEAD
{
    /**
     *
     */
    const CHUNK_SIZE_LEN = 2;
    /**
     *
     */
    const AEAD_TAG_LEN = 16;

    /**
     *
     */
    const CRYPTO_ERROR = -1;
    /**
     *
     */
    const CRYPTO_NEED_MORE = 0;
    /**
     *
     */
    const CRYPTO_OK = 1;

    /**
     *
     */
    const CHUNK_SIZE_MASK = 0x3FFF;
    /**
     * @var string
     */
    protected string $_aead_tail = "";
    /**
     * @var string
     */
    protected string $_aead_subkey;
    /**
     * @var string
     */
    protected string $_aead_iv;
    /**
     * @var int
     */
    protected int $_aead_chunk_id = 0;
    /**
     * @var bool
     */
    protected bool $_sodium_support;

    /**
     * @var array[]
     */
    protected static array $_methodSupported = array(
        'aes-128-gcm' => array(16, 12),
        'aes-192-gcm' => array(24, 12),
        'aes-256-gcm' => array(32, 12),
        'chacha20-poly1305' => array(32, 8),
        'chacha20-ietf-poly1305' => array(32, 12),
        'xchacha20-ietf-poly1305' => array(32, 24),
    );

    /**
     * @param string $_algorithm
     * @param string $_aead_subkey
     * @param string $salt
     * @param bool $_aead_encipher_all
     */
    public function __construct(protected string $_algorithm, string $_aead_subkey, string $salt, protected bool $_aead_encipher_all = false)
    {
        $this->_aead_iv = str_repeat("\x00", self::$_methodSupported[$_algorithm][1]);
        /* subkey生成 */
        $this->_aead_subkey = hash_hkdf("sha1", $_aead_subkey, strlen($_aead_subkey), "ss-subkey", $salt);
        if (function_exists('sodium_increment')) {
            $this->_sodium_support = true;
        } else {
            $this->_sodium_support = false;
        }
    }

    /**
     * @param $nonce
     * @return void
     */
    protected function nonce_increment(&$nonce): void
    {
        $c = 1;
        $len = strlen($nonce);
        for ($i = 0; $i < $len; $i++) {
            $c += ord($nonce[$i]);
            $nonce[$i] = chr($c & 0xff);
            $c >>= 8;
        }
    }
}