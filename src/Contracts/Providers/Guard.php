<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Contracts\Providers;


interface Guard
{
    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check();

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest();

    /**
     * Get the currently authenticated user.
     *
     * @return \Kangst\JWTAuth\Contracts\Providers\Authenticatable|null
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-15 14:11:47
     */
    public function user();

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id();

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = []);

    /**
     * Set the current user.
     *
     * @param \Kangst\JWTAuth\Contracts\Providers\Authenticatable $user
     * @return mixed
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-15 14:12:56
     */
    public function setUser(Authenticatable $user);
}