<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Claims;


use Kangst\JWTAuth\Support\Utils;
use think\helper\Str;
use think\Request;

class Factory
{
    /**
     * @var Request
     */
    protected $request;

    /**
     * The TTL.
     *
     * @var int
     */
    protected $ttl = 60;

    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;

    /**
     * The classes map.
     *
     * @var array
     */
    private $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    /**
     * Factory constructor.
     *
     * @param Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param $name
     * @param $value
     * @return Custom
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:20:42
     */
    public function get($name, $value)
    {
        if ($this->has($name)) {
            $claim = new $this->classMap[$name]($value);

            return method_exists($claim, 'setLeeway') ?
                $claim->setLeeway($this->leeway) :
                $claim;
        }
        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     *
     * @param  string  $name
     *
     * @return bool
     */
    public function has($name)
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * Generate the initial value and return the Claim instance.
     *
     * @param $name
     * @return Custom
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:21:39
     */
    public function make($name)
    {
        return $this->get($name, $this->$name());
    }

    /**
     * Get the Issuer (iss) claim.
     *
     * @return string
     */
    public function iss()
    {
        return $this->request->url();
    }

    /**
     * Get the Issued At (iat) claim.
     *
     * @return int
     */
    public function iat()
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the Expiration (exp) claim.
     *
     * @return int
     */
    public function exp()
    {
        return Utils::now()->addMinutes($this->ttl)->getTimestamp();
    }

    /**
     * Get the Not Before (nbf) claim.
     *
     * @return int
     */
    public function nbf()
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the JWT Id (jti) claim.
     *
     * @return string
     */
    public function jti()
    {
        return Str::random();
    }

    /**
     * Add a new claim mapping.
     *
     * @param  string  $name
     * @param  string  $classPath
     *
     * @return $this
     */
    public function extend($name, $classPath)
    {
        $this->classMap[$name] = $classPath;

        return $this;
    }

    /**
     * Set the request instance.
     *
     * @param Request $request
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:23:48
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Set the token ttl (in minutes).
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     *
     * @return int
     */
    public function getTTL()
    {
        return $this->ttl;
    }

    /**
     * Set the leeway in seconds.
     *
     * @param  int  $leeway
     *
     * @return $this
     */
    public function setLeeway($leeway)
    {
        $this->leeway = $leeway;

        return $this;
    }
}