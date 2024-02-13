<?php

namespace localzet\ShadowSocks\Cipher\CFB;

use localzet\ShadowSocks\Cipher\CipherInterface;

/**
 *
 */
class CfbEncipher implements CipherInterface
{
    /**
     * @var string
     */
    protected string $_algorithm;
    /**
     * @var
     */
    protected $_algorithm_openssl;
    /**
     * @var
     */
    protected $_key;
    /**
     * @var
     */
    protected $_iv;
    /**
     * @var
     */
    protected $_tail = '';
    /**
     * @var false|int
     */
    protected int|false $_block_size;

    /**
     * @param $algorithm
     * @param $key
     * @param $iv
     */
    public function __construct($algorithm, $key, $iv)
    {
        $this->_algorithm = $algorithm;
        $this->_key = $key;
        $this->_iv = $iv;
        $this->_block_size = openssl_cipher_iv_length($this->_algorithm);
    }

    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string
    {
        if (strlen($buffer) == 0)
            return '';
        $tl = strlen($this->_tail);
        if ($tl)
            $buffer = $this->_tail . $buffer;
        $b = openssl_encrypt($buffer, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($buffer);
        $mod = $dataLength % $this->_block_size;
        if ($dataLength >= $this->_block_size) {
            $iPos = -($mod + $this->_block_size);
            $this->_iv = substr($b, $iPos, $this->_block_size);
        }
        $this->_tail = $mod != 0 ? substr($buffer, -$mod) : '';
        return $result;
    }
}
