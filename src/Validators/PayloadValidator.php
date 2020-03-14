<?php
/*
 * This file is part of think-jwt.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Validators;


use Kangst\JWTAuth\Claims\Collection;
use Kangst\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends ValidatorAbstract
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param array $value
     * @return Collection
     * @throws TokenInvalidException
     * @throws \Kangst\JWTAuth\Exceptions\TokenExpiredException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2019-11-20 13:57:33
     */
    public function check($value)
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param  \Kangst\JWTAuth\Claims\Collection  $claims
     *
     * @throws \Kangst\JWTAuth\Exceptions\TokenInvalidException
     *
     * @return void
     */
    protected function validateStructure(Collection $claims)
    {
        if ($this->requiredClaims && ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @param  \Kangst\JWTAuth\Claims\Collection  $claims
     *
     * @throws \Kangst\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Kangst\JWTAuth\Exceptions\TokenInvalidException
     *
     * @return \Kangst\JWTAuth\Claims\Collection
     */
    protected function validatePayload(Collection $claims)
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param  \Kangst\JWTAuth\Claims\Collection  $claims
     *
     * @throws \Kangst\JWTAuth\Exceptions\TokenExpiredException
     *
     * @return \Kangst\JWTAuth\Claims\Collection
     */
    protected function validateRefresh(Collection $claims)
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
