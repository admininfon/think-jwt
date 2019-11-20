<?php


namespace Kangst\JWTAuth;


use Lcobucci\JWT\Signature;

class Token extends \Lcobucci\JWT\Token
{
    public function __construct(array $headers = ['alg' => 'none'], array $claims = [], Signature $signature = null, array $payload = ['', ''])
    {
        parent::__construct($headers, $claims, $signature, $payload);
    }
}
