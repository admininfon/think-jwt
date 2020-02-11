<?php
/*
 * This file is part of Auth.php.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Contracts\Providers;


interface Auth
{
    /**
     * Check a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return mixed
     */
    public function byCredentials(array $credentials);

    /**
     * Authenticate a user via the id.
     *
     * @param  mixed  $id
     *
     * @return mixed
     */
    public function byId($id);

    /**
     * Get the currently authenticated user.
     *
     * @return mixed
     */
    public function user();
}