<?php


namespace Kangst\JWTAuth\Providers\JWT;


use Kangst\JWTAuth\Contracts\Providers\JWT;
use Kangst\JWTAuth\Exceptions\JWTException;
use Kangst\JWTAuth\Exceptions\TokenInvalidException;
use Namshi\JOSE\JWS;
use Namshi\JOSE\Signer\OpenSSL\PublicKey;

class Namshi extends Provider implements JWT
{
    /**
     * The JWT.
     *
     * @var \Namshi\JOSE\JWS;
     */
    protected $jws;

    /**
     * Constructor.
     *
     * @param  \Namshi\JOSE\JWS  $jws
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     *
     * @return void
     */
    public function __construct(JWS $jws, $secret, $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);

        $this->jws = $jws;
    }

    /**
     * Create a JSON Web Token.
     *
     * @param array $payload
     * @return string
     * @throws JWTException
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-11 15:37:46
     */
    public function encode(array $payload)
    {
        try {
            $this->jws->setPayload($payload)->sign($this->getSigningKey(), $this->getPassphrase());

            return (string) $this->jws->getTokenString();
        } catch (\Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param string $token
     * @return array
     * @throws JWTException
     * @throws TokenInvalidException
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-11 15:42:32
     */
    public function decode($token)
    {
        try {
            // Let's never allow insecure tokens
            $jws = $this->jws->load($token, false);
        } catch (\InvalidArgumentException $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        if (! $jws->verify($this->getVerificationKey(), $this->getAlgo())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (array) $jws->getPayload();
    }

    /**
     * @inheritDoc
     */
    protected function isAsymmetric()
    {
        try {
            return (new \ReflectionClass(sprintf('Namshi\\JOSE\\Signer\\OpenSSL\\%s', $this->getAlgo())))->isSubclassOf(PublicKey::class);
        } catch (\ReflectionException $e) {
            throw new JWTException('The given algorithm could not be found', $e->getCode(), $e);
        }
    }
}