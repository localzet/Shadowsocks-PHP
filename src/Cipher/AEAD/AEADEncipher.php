<?php

namespace localzet\ShadowSocks\Cipher\AEAD;

use localzet\ShadowSocks\Cipher\CipherInterface;
use SodiumException;

/**
 * @author walkor <walkor@workerman.net>
 * @author Ivan Zorin <creator@localzet.com>
 */
class AEADEncipher extends AbstractAEAD implements CipherInterface
{
    /**
     * @param string $buffer
     * @return string
     * @throws SodiumException
     */
    public function update(string $buffer): string
    {
        //UDP
        if ($this->_aead_encipher_all) {
            $err = $this->aead_encrypt_all($this->_aead_iv, $this->_aead_subkey, $buffer);
            if ($err == static::CRYPTO_ERROR) {
                echo "[" . __FILE__ . " " . __LINE__ . "] Ошибка кодирования AEAD\n";
                return '';
            }
            return $buffer;
        }
        //TCP
        $result = '';
        while (strlen($buffer) > 0) {
            $temp = '';
            $err = $this->aead_chunk_encrypt($this->_aead_iv, $this->_aead_subkey, $buffer, $temp);
            if ($err == static::CRYPTO_ERROR) {
                echo "[" . __FILE__ . " " . __LINE__ . "] Ошибка кодирования AEAD\n";
                return '';
            }
            $result .= $temp;
        }

        return $result;
    }

    /**
     * @param $iv
     * @param $subkey
     * @param $buffer
     * @return int
     * @throws SodiumException
     */
    protected function aead_encrypt_all($iv, $subkey, &$buffer): int
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +-------------------+-------------+
         *  | encrypted payload | payload tag |
         *  +-------------------+-------------+
         *  |        n          |     16      |
         *  +-------------------+-------------+
         *
         */
        $buffer = $this->aead_encrypt($buffer, '', $iv, $subkey);
        return static::CRYPTO_OK;
    }

    /**
     * @param $iv
     * @param $subkey
     * @param $buffer
     * @param $result
     * @return int
     * @throws SodiumException
     */
    protected function aead_chunk_encrypt(&$iv, $subkey, &$buffer, &$result): int
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +--------------------------+------------+-------------------+-------------+
         *  | encrypted payload length | length tag | encrypted payload | payload tag |
         *  +--------------------------+------------+-------------------+-------------+
         *  |             2            |     16     |        n          |     16      |
         *  +--------------------------+------------+-------------------+-------------+
         *
         */
        $plen = strlen($buffer);
        if ($plen > static::CHUNK_SIZE_MASK) {
            $plen = static::CHUNK_SIZE_MASK;
        }
        $data = substr($buffer, 0, $plen);
        $plen_bin = pack('n', $plen);
        $result .= $this->aead_encrypt($plen_bin, '', $iv, $subkey);
        if (strlen($result) != static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN) {
            return static::CRYPTO_ERROR;
        }
        if ($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $result .= $this->aead_encrypt($data, '', $iv, $subkey);
        if (strlen($result) != 2 * static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN + $plen) {
            return static::CRYPTO_ERROR;
        }
        if ($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $this->_aead_chunk_id++;
        $buffer = substr($buffer, $plen);
        return static::CRYPTO_OK;
    }

    /**
     * @param $msg
     * @param $ad
     * @param $nonce
     * @param $key
     * @return string
     * @throws SodiumException
     */
    protected function aead_encrypt($msg, $ad, $nonce, $key): string
    {
        if ($this->_sodium_support) {
            switch ($this->_algorithm) {
                case 'aes-256-gcm':
                    return sodium_crypto_aead_aes256gcm_encrypt($msg, $ad, $nonce, $key);
                case 'chacha20-poly1305':
                    return sodium_crypto_aead_chacha20poly1305_encrypt($msg, $ad, $nonce, $key);
                case 'chacha20-ietf-poly1305':
                    return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($msg, $ad, $nonce, $key);
                case 'xchacha20-ietf-poly1305':
                    return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($msg, $ad, $nonce, $key);
                default:
            }
        }
        switch ($this->_algorithm) {
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                $tag = '';
                $data = openssl_encrypt($msg, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                return $data . $tag;
            default:
                echo "unsupported encryption algorithm, please enable sodium expansion\n";
                return '';
        }
    }
}
