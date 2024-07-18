<?php

namespace localzet\ShadowSocks\Cipher\CFB;

abstract class AbstractCFB
{
    /**
     * @var
     */
    protected $_tail = '';
    /**
     * @var false|int
     */
    protected int|false $_block_size;

    /**
     * @param string $_algorithm
     * @param $_key
     * @param $_iv
     */
    public function __construct(protected string $_algorithm, protected $_key, protected $_iv)
    {
        $this->_block_size = openssl_cipher_iv_length($this->_algorithm);
    }
}