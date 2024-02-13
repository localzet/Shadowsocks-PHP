<?php

namespace localzet\ShadowSocks\Cipher;

/**
 *
 */
class CTREncipher implements CipherInterface
{
    /**
     *
     */
    const BLOCK_SIZE = 64;
    /**
     * @var
     */
    protected $_algorithm;
    /**
     * @var string
     */
    protected $_algorithm_openssl;
    /**
     * @var
     */
    protected $_key;
    /**
     * @var
     */
    protected $_tail;
    /**
     * @var false|int
     */
    protected $_block_size;

    /**
     * @param $algorithm
     * @param $key
     * @param $iv
     */
    public function __construct($algorithm, $key, $iv)
    {
        $this->_algorithm = $algorithm;
        $this->_key = $key;
        $this->_nonce = $iv;
        if (function_exists('gmp_init')) {
            $this->_counter = gmp_init('0');
            $this->_gmp_support = true;
        } else {
            $this->_counter = 0;
            $this->_gmp_support = false;
        }
        if (str_contains($algorithm, "chacha20")) {
            $this->_block_size = static::BLOCK_SIZE;
            $this->_algorithm_openssl = 'chacha20';
        } else {
            $this->_block_size = openssl_cipher_iv_length($this->_algorithm);
            $this->_algorithm_openssl = $this->_algorithm;
        }
    }

    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string
    {
        if (strlen($buffer) == 0)
            return '';
        if ($this->_gmp_support) {
            $iv = $this->counter_mode_gen_iv_by_gmp();
            $this->_counter = gmp_add($this->_counter, strval(strlen($buffer)));
        } else {
            $iv = $this->counter_mode_gen_iv();
            $this->_counter += strlen($buffer);
        }

        $tl = strlen($this->_tail);
        if ($tl)
            $buffer = $this->_tail . $buffer;
        $b = openssl_encrypt($buffer, $this->_algorithm_openssl, $this->_key, OPENSSL_RAW_DATA, $iv);
        $result = substr($b, $tl);
        $dataLength = strlen($buffer);
        $mod = $dataLength % $this->_block_size;
        $this->_tail = $mod != 0 ? substr($buffer, -$mod) : '';
        return $result;
    }

    /**
     * @return string
     */
    protected function counter_mode_gen_iv_by_gmp(): string
    {
        $counter = gmp_div_q($this->_counter, strval($this->_block_size));
        switch ($this->_algorithm) {
            case 'chacha20-ietf':
                //more: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/chacha20
                /* The IETF variant increases the nonce size to 96 bits,
                 * but reduces the counter size down to 32 bits, allowing
                 * only up to 256 GB of data to be safely encrypted with a
                 * given (key, nonce) pair.
                 */
                $counter_pack = gmp_export($counter, 4, GMP_LSW_FIRST);
                $counter_pack = str_pad($counter_pack, 4, "\0", STR_PAD_LEFT);
                return $counter_pack . $this->_nonce;
            case 'chacha20':
                /* The original ChaCha20 cipher with a 64-bit nonce and a 64-bit counter,
                 * allowing a practically unlimited amount of data to be encrypted with the same
                 * (key, nonce) pair
                 */
                $counter_pack = gmp_export($counter, 8, GMP_LSW_FIRST);
                $counter_pack = str_pad($counter_pack, 8, "\0", STR_PAD_LEFT);
                return $counter_pack . $this->_nonce;
            case 'aes-128-ctr':
            case 'aes-192-ctr':
            case 'aes-256-ctr':
                $nonce = gmp_import($this->_nonce, 1, GMP_MSW_FIRST);
                $counter_pack = gmp_export(gmp_add($nonce, $counter), 1, GMP_MSW_FIRST);
                return str_pad($counter_pack, 16, "\0", STR_PAD_LEFT);
            default:
                return $this->_iv;
        }
    }

    /**
     * @return string
     */
    protected function counter_mode_gen_iv(): string
    {
        $counter = intval($this->_counter / $this->_block_size);
        switch ($this->_algorithm) {
            case 'chacha20-ietf':
                $counter_pack = pack("V", $counter);
                return $counter_pack . $this->_nonce;
            case 'chacha20':
                /* 此处为了兼容32位系统，使用32位counter */
                $counter_pack = pack("V2", $counter, 0);
                return $counter_pack . $this->_nonce;
            case 'aes-128-ctr':
            case 'aes-192-ctr':
            case 'aes-256-ctr':
                $counter_pack = pack("N", $counter);
                return $this->msb_number_add($this->_nonce, $counter_pack);
            default:
                return $this->_iv;
        }
    }

    /**
     * @param $a
     * @param $b
     * @return string
     */
    protected function msb_number_add($a, $b): string
    {
        $la = strlen($a);
        $lb = strlen($b);
        if ($la > $lb) {
            $base = strrev($a);
            $add = strrev($b);
            $base_len = $la;
            $add_len = $lb;
        } else {
            $base = strrev($b);
            $add = strrev($a);
            $base_len = $lb;
            $add_len = $la;
        }
        $c = 0;
        for ($i = 0; $i < $base_len; $i++) {
            if ($i < $add_len)
                $c += ord($add[$i]);
            $sum = $c + ord($base[$i]);
            $base[$i] = chr($sum % 256);
            $c = intval($sum / 256);
        }
        return strrev($base);
    }
}
