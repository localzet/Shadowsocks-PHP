<?php

namespace localzet\ShadowSocks\Cipher\CFB;

use localzet\ShadowSocks\Cipher\CipherInterface;

/**
 * @author walkor <walkor@workerman.net>
 * @author Ivan Zorin <creator@localzet.com>
 */
class CFBDecipher extends AbstractCFB implements CipherInterface
{
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
        $b = openssl_decrypt($buffer, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($buffer);
        $mod = $dataLength % $this->_block_size;
        if ($dataLength >= $this->_block_size) {
            $iPos = -($mod + $this->_block_size);
            $this->_iv = substr($buffer, $iPos, $this->_block_size);
        }
        $this->_tail = $mod != 0 ? substr($buffer, -$mod) : '';
        return $result;
    }
}
