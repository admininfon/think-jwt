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


trait RefreshFlow
{
    /**
     * The refresh flow flag.
     *
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     * Set the refresh flow flag.
     *
     * @param  bool  $refreshFlow
     *
     * @return $this
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
