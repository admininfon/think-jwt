<?php

// 加载composer
require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Class Run
 */
class Run
{
    /**
     * enJWTToken
     *
     * @return string
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-11 16:28:02
     */
    private function enJWTToken()
    {
        $jwt = new \Kangst\JWTAuth\JWT();
        return (string) $jwt;
    }

    /**
     * deJWTToken
     *
     * @param string $token
     * @return mixed
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-11 16:28:15
     */
    private function deJWTToken(string $token)
    {
        $jwt = new \Kangst\JWTAuth\JWT();
        $jwt->verify($token);
        return $jwt->decode($token);
    }

    public static function send()
    {
        $run = new Run();
        $token = $run->enJWTToken();
        $data = $run->deJWTToken($token);
        var_dump($token, var_export($data, true));
    }
}

Run::send();
