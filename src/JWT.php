<?php
/*
 * This file is part of think-jwt.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth;


use Kangst\JWTAuth\Providers\Auth\Auth;
use think\Config;

class JWT
{
    /**
     * @var string|null
     */
    protected $guard = 'default';

    /**
     * @var Auth
     */
    protected $auth;

    public function __construct($guard = null)
    {
        if (!empty($guard)) {
            $this->guard = $guard;
        }

        $config = new Config();
        $provider = $config->get('jwt.guards.'. $this->guard .'.provider');
        $auth = new $provider();
        $this->auth = new Auth($auth);
    }
}
