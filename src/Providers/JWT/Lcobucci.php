<?php
/*
 * This file is part of think-jwt.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Providers\JWT;


use Kangst\JWTAuth\Claims\Collection;
use Kangst\JWTAuth\Contracts\Providers\JWT;
use Kangst\JWTAuth\Exceptions\JWTException;
use Kangst\JWTAuth\Exceptions\TokenInvalidException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;

class Lcobucci extends Provider implements JWT
{
    /**
     * The Builder instance.
     *
     * @var \Lcobucci\JWT\Builder
     */
    protected $builder;

    /**
     * The Parser instance.
     *
     * @var \Lcobucci\JWT\Parser
     */
    protected $parser;

    /**
     * The Signer instance.
     *
     * @var \Lcobucci\JWT\Signer
     */
    protected $signer;

    /**
     * Lcobucci constructor.
     * @param Builder $builder
     * @param Parser $parser
     * @param $secret
     * @param $algo
     * @param array $keys
     * @throws JWTException
     */
    public function __construct(Builder $builder, Parser $parser, $secret, $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);

        $this->builder = $builder;
        $this->parser = $parser;
        $this->signer = $this->getSigner();
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    /**
     * Get the signer instance.
     *
     * @return \Lcobucci\JWT\Signer
     * @throws JWTException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-01-09 15:59:21
     */
    protected function getSigner()
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo];
    }

    /**
     * encode
     *
     * @param array $payload
     * @return string
     * @throws JWTException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-01-09 16:04:17
     */
    public function encode(array $payload)
    {
        // Remove the signature on the builder instance first.
        $this->builder->unsign();

        try {
            foreach ($payload as $key => $value) {
                $this->builder->set($key, $value);
            }
            $this->builder->sign($this->signer, $this->getSigningKey());
        } catch (\Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return (string) $this->builder->getToken();
    }

    /**
     * decode
     *
     * @param string $token
     * @return array
     * @throws JWTException
     * @throws TokenInvalidException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-01-09 16:06:11
     */
    public function decode($token)
    {
        try {
            $jwt = $this->parser->parse($token);
        } catch (\Exception $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $jwt->verify($this->signer, $this->getVerificationKey())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (new Collection($jwt->getClaims()))->map(function ($claim) {
            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
    }

    /**
     * @inheritDoc
     */
    protected function isAsymmetric()
    {
        $reflect = new \ReflectionClass($this->signer);

        return $reflect->isSubclassOf(Rsa::class) || $reflect->isSubclassOf(Hmac::class);
    }
}
