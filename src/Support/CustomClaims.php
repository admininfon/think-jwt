<?php
/*
 * This file is part of think-jwt.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Support;


trait CustomClaims
{
    /**
     * Custom claims.
     *
     * @var array
     */
    protected $customClaims = array();

    /**
     * Set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function customClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * Alias to set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function claims(array $customClaims)
    {
        return $this->customClaims($customClaims);
    }

    /**
     * Get the custom claims.
     *
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->customClaims;
    }
}
