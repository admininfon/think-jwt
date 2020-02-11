<?php
/*
 * This file is part of Auth.php.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Providers\Auth;


use  Kangst\JWTAuth\Contracts\Providers\Auth as AuthInterface;

class Auth extends Provider implements AuthInterface
{

    /**
     * @inheritDoc
     */
    public function byCredentials(array $credentials)
    {
        // TODO: Implement byCredentials() method.
    }

    /**
     * @inheritDoc
     */
    public function byId($id)
    {
        // TODO: Implement byId() method.
    }

    /**
     * @inheritDoc
     */
    public function user()
    {
        // TODO: Implement user() method.
    }
}