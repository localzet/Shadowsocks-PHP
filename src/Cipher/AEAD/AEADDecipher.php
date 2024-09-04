<?php

namespace localzet\ShadowSocks\Cipher\AEAD;

use localzet\ShadowSocks\Cipher\CipherInterface;
use SodiumException;

/**
 * @author walkor <walkor@workerman.net>
 * @author Ivan Zorin <creator@localzet.com>
 */
class AEADDecipher extends AbstractAEAD implements CipherInterface
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
            $err = $this->aead_decrypt_all($this->_aead_iv, $this->_aead_subkey, $buffer);
            if ($err == static::CRYPTO_ERROR) {
                echo "[" . __FILE__ . " " . __LINE__ . "] Ошибка декодирования AEAD\n";
                return '';
            }
            return $buffer;
        }
        //TCP
        $tl = strlen($this->_aead_tail);
        if ($tl) {
            $buffer = $this->_aead_tail . $buffer;
            $this->_aead_tail = '';
        }

        $result = '';
        while (strlen($buffer) > 0) {
            $err = $this->aead_chunk_decrypt($this->_aead_iv, $this->_aead_subkey, $buffer, $result);
            if ($err == static::CRYPTO_ERROR) {
                echo "[ " . __LINE__ . "] Ошибка декодирования AEAD\n";
                return '';
            } else if ($err == static::CRYPTO_NEED_MORE) {
                if (strlen($buffer) == 0) {
                    echo "[ " . __LINE__ . "] Ошибка декодирования AEAD\n";
                    return '';
                } else {
                    $this->_aead_tail .= $buffer;
                    //echo "[ " . __LINE__ . "]" . "AEAD decrypt tail\n";
                    break;
                }
            }
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
    public function aead_decrypt_all($iv, $subkey, &$buffer): int
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
        //验证chunk长度
        if (strlen($buffer) <= static::AEAD_TAG_LEN) {
            return static::CRYPTO_ERROR;
        }

        $buffer = $this->aead_decrypt($buffer, '', $iv, $subkey);
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
    protected function aead_chunk_decrypt(&$iv, $subkey, &$buffer, &$result): int
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
        //验证chunk长度
        if (strlen($buffer) <= 2 * static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN) {
            return static::CRYPTO_NEED_MORE;
        }

        $payload_length_enc_length = static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN;
        $payload_length_enc = substr($buffer, 0, $payload_length_enc_length);

        $mlen = $this->aead_decrypt($payload_length_enc, '', $iv, $subkey);
        if (strlen($mlen) != static::CHUNK_SIZE_LEN) {
            echo "[ " . __LINE__ . "]" . "mlen error! id: " . $this->_aead_chunk_id . "\n";
            return static::CRYPTO_ERROR;
        }
        $payload_length = unpack('n', $mlen);
        $payload_length = intval($payload_length[1]) & static::CHUNK_SIZE_MASK;
        $payload_enc_length = $payload_length + static::AEAD_TAG_LEN;
        //验证payload长度
        if (strlen($buffer) - $payload_length_enc_length < $payload_enc_length) {
            return static::CRYPTO_NEED_MORE;
        }
        $buffer = substr($buffer, $payload_length_enc_length);
        $payload_enc = substr($buffer, 0, $payload_enc_length);
        $buffer = substr($buffer, $payload_enc_length);
        if ($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $result .= $this->aead_decrypt($payload_enc, '', $iv, $subkey);
        if ($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $this->_aead_chunk_id++;
        return static::CRYPTO_OK;
    }

    /**
     * @param $msg
     * @param $ad
     * @param $nonce
     * @param $key
     * @return false|string
     * @throws SodiumException
     */
    protected function aead_decrypt($msg, $ad, $nonce, $key): false|string
    {
        if ($this->_sodium_support) {
            switch ($this->_algorithm) {
                case 'aes-256-gcm':
                    return sodium_crypto_aead_aes256gcm_decrypt($msg, $ad, $nonce, $key);
                case 'chacha20-poly1305':
                    return sodium_crypto_aead_chacha20poly1305_decrypt($msg, $ad, $nonce, $key);
                case 'chacha20-ietf-poly1305':
                    return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($msg, $ad, $nonce, $key);
                case 'xchacha20-ietf-poly1305':
                    return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($msg, $ad, $nonce, $key);
            }
        }

        switch ($this->_algorithm) {
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                $data_len = strlen($msg) - static::AEAD_TAG_LEN;
                $data = substr($msg, 0, $data_len);
                $tag = substr($msg, $data_len);
                return openssl_decrypt($data, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
        }

        echo "Алгоритм не поддерживается! Пожалуйста, активируйте sodium\n";
        return '';
    }
}