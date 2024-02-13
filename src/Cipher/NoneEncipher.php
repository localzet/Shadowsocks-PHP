<?php

namespace localzet\ShadowSocks\Cipher;

/**
 *
 */
class NoneEncipher implements CipherInterface
{
    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string
    {
        return $buffer;
    }
}
