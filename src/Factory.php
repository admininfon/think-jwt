<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth;


use Kangst\JWTAuth\Claims\ClaimInterface;
use Kangst\JWTAuth\Claims\Collection;
use Kangst\JWTAuth\Support\CustomClaims;
use Kangst\JWTAuth\Support\RefreshFlow;
use Kangst\JWTAuth\Validators\PayloadValidator;
use Kangst\JWTAuth\Claims\Factory as ClaimFactory;

class Factory
{
    use CustomClaims, RefreshFlow;

    /**
     * @var \Kangst\JWTAuth\Claims\Factory
     */
    protected $claimFactory;

    /**
     * @var PayloadValidator
     */
    protected $validator;

    /**
     * The default claims.
     *
     * @var array
     */
    protected $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    /**
     * @var Collection
     */
    protected $claims;

    /**
     * Factory constructor.
     *
     * @param ClaimFactory     $claimFactory
     * @param PayloadValidator $payloadValidator
     */
    public function __construct(ClaimFactory $claimFactory, PayloadValidator $payloadValidator)
    {
        $this->claimFactory = $claimFactory;
        $this->validator = $payloadValidator;
        $this->claims = new Collection;
    }

    /**
     * make
     *
     * @param bool $resetClaims
     * @return Payload
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:50:41
     */
    public function make($resetClaims = false)
    {
        if ($resetClaims) {
            $this->emptyClaims();
        }

        return $this->withClaims($this->buildClaimsCollection());
    }

    /**
     * emptyClaims
     *
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:45:04
     */
    public function emptyClaims()
    {
        $this->claims = new Collection;

        return $this;
    }

    protected function addClaims(array $claims)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * addClaim
     *
     * @param $name
     * @param $value
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:46:44
     */
    protected function addClaim($name, $value)
    {
        $this->claims->push($name, $value);

        return $this;
    }

    /**
     * buildClaims
     *
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:47:22
     */
    protected function buildClaims()
    {
        // remove the exp claim if it exists and the ttl is null
        if ($this->claimFactory->getTTL() === null && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    /**
     * resolveClaims
     *
     * @return Collection
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:47:59
     */
    protected function resolveClaims()
    {
        return $this->claims->map(function ($value, $name) {
            return $value instanceof ClaimInterface ? $value : $this->claimFactory->get($name, $value);
        });
    }

    /**
     * buildClaimsCollection
     *
     * @return Collection
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:48:12
     */
    public function buildClaimsCollection()
    {
        return $this->buildClaims()->resolveClaims();
    }

    /**
     * withClaims
     *
     * @param Collection $claims
     * @return Payload
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:48:28
     */
    public function withClaims(Collection $claims)
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * setDefaultClaims
     *
     * @param array $claims
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:48:40
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * setTTL
     *
     * @param $ttl
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:48:51
     */
    public function setTTL($ttl)
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    /**
     * Helper to get the ttl.
     *
     * @return int
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:49:02
     */
    public function getTTL()
    {
        return $this->claimFactory->getTTL();
    }

    /**
     * Get the default claims.
     *
     * @return array
     */
    public function getDefaultClaims()
    {
        return $this->defaultClaims;
    }

    /**
     * validator
     *
     * @return PayloadValidator
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 22:49:51
     */
    public function validator()
    {
        return $this->validator;
    }

    /**
     * Magically add a claim.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @return $this
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}