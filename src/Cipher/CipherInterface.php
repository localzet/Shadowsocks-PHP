<?php

namespace localzet\ShadowSocks\Cipher;

/**
 * @author walkor <walkor@workerman.net>
 * @author Ivan Zorin <creator@localzet.com>
 */
interface CipherInterface
{
    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string;
}