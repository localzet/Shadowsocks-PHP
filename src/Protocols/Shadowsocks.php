<?php

namespace localzet\ShadowSocks\Protocols;

/**
 * 协议类
 * 处理明文数据
 * @author hxdyxd<hxdyxd@gmail.com>
 */
class Shadowsocks
{
    /**
     * @var AuthAes|Origin
     */
    protected AuthAes|Origin $_protocol;

    /**
     * @param $key
     * @param $iv
     * @param $protocol
     * @param $param
     */
    public function __construct($key, $iv, $protocol, $param)
    {
        $this->_protocol = match ($protocol) {
            'auth_aes128_md5', 'auth_aes128_sha1' => new AuthAes($key, $iv, $protocol, $param),
            default => new Origin(),
        };
    }

    //客户端发送到服务端数据加密前

    /**
     * @param $plaindata
     * @return mixed|string
     */
    public function ClientPreEncrypt($plaindata): mixed
    {
        return $this->_protocol->ClientPreEncrypt($plaindata);
    }

    //客户端收到服务端数据解密后

    /**
     * @param $plaindata
     * @return mixed|string
     */
    public function ClientPostDecrypt($plaindata): mixed
    {
        return $this->_protocol->ClientPostDecrypt($plaindata);
    }

    //服务端发送到客户端数据加密前

    /**
     * @param $plaindata
     * @return mixed|string
     */
    public function ServerPreEncrypt($plaindata): mixed
    {
        return $this->_protocol->ServerPreEncrypt($plaindata);
    }

    //服务端收到客户端数据解密后

    /**
     * @param $plaindata
     * @return false|mixed|string
     */
    public function ServerPostDecrypt($plaindata): mixed
    {
        return $this->_protocol->ServerPostDecrypt($plaindata);
    }

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ClientUdpPreEncrypt($plaindata): mixed
    {
        return $plaindata;
    }

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ClientUdpPostDecrypt($plaindata): mixed
    {
        return $plaindata;
    }

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ServerUdpPreEncrypt($plaindata): mixed
    {
        return $plaindata;
    }

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ServerUdpPostDecrypt($plaindata): mixed
    {
        return $plaindata;
    }
}




