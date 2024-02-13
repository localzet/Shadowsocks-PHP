<?php

namespace localzet\ShadowSocks\Cipher;

/**
 *
 */
class RC4Encipher implements CipherInterface
{
    /**
     * @var array
     */
    protected $s;
    /**
     * @var int
     */
    protected $_i;
    /**
     * @var int
     */
    protected $_j;

    /**
     * @param $key
     */
    public function __construct($key)
    {
        $this->s = array();
        for ($i = 0; $i < 256; $i++) {
            $this->s[$i] = $i;
        }

        $j = 0;
        $key_len = strlen($key);
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $this->s[$i] + ord($key[$i % $key_len])) % 256;
            //swap
            $x = $this->s[$i];
            $this->s[$i] = $this->s[$j];
            $this->s[$j] = $x;
        }
        $this->_i = 0;
        $this->_j = 0;
    }

    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string
    {
        $i = $this->_i;
        $j = $this->_j;
        $out_buf = '';
        $data_len = strlen($buffer);
        for ($y = 0; $y < $data_len; $y++) {
            $i = ($i + 1) % 256;
            $j = ($j + $this->s[$i]) % 256;
            //swap
            $x = $this->s[$i];
            $this->s[$i] = $this->s[$j];
            $this->s[$j] = $x;
            $out_buf .= $buffer[$y] ^ chr($this->s[($this->s[$i] + $this->s[$j]) % 256]);
        }
        $this->_i = $i;
        $this->_j = $j;
        return $out_buf;
    }
}
