<?php

namespace localzet\ShadowSocks\Protocols;

/**
 *
 */
class Origin
{
    /**
     *
     */
    public function __construct()
    {
//        Оно меня заебало
//        echo "OriginProtocol \n";
    }

    //客户端发送到服务端数据加密前

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ClientPreEncrypt($plaindata): mixed
    {
        return $plaindata;
    }

    //客户端收到服务端数据解密后

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ClientPostDecrypt($plaindata): mixed
    {
        return $plaindata;
    }

    //服务端发送到客户端数据加密前

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ServerPreEncrypt($plaindata): mixed
    {
        return $plaindata;
    }

    //服务端收到客户端数据解密后

    /**
     * @param $plaindata
     * @return mixed
     */
    public function ServerPostDecrypt($plaindata): mixed
    {
        return $plaindata;
    }
}