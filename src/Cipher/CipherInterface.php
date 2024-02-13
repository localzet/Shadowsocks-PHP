<?php

namespace localzet\ShadowSocks\Cipher;

/**
 *
 */
interface CipherInterface
{
    /**
     * @param string $buffer
     * @return string
     */
    public function update(string $buffer): string;
}