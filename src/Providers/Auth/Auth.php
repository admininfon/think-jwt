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


use Kangst\JWTAuth\Contracts\Providers\Auth as AuthInterface;
use Kangst\JWTAuth\JWTGuard;

class Auth extends Provider implements AuthInterface
{
    /**
     * The authentication guard.
     *
     * @var
     */
    protected $auth;

    public function __construct(JWTGuard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Check a user's credentials.
     *
     * @param array $credentials
     * @return bool
     * @throws \Kangst\JWTAuth\Exceptions\TokenInvalidException
     * @throws \Kangst\JWTAuth\Exceptions\JWTGuardException
     */
    public function byCredentials(array $credentials)
    {
        return $this->auth->once($credentials);
    }

    /**
     * Authenticate a user via the id.
     *
     * @param mixed $id
     * @return bool
     * @throws \Kangst\JWTAuth\Exceptions\JWTGuardException
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    public function byId($id)
    {
        return $this->auth->onceUsingId($id);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Kangst\JWTAuth\Contracts\Providers\Authenticatable|GenericUser|mixed|null
     * @throws \Kangst\JWTAuth\Exceptions\JWTException
     * @throws \Kangst\JWTAuth\Exceptions\JWTGuardException
     * @throws \Kangst\JWTAuth\Exceptions\TokenBlacklistedException
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:39:47
     */
    public function user()
    {
        return $this->auth->user();
    }
}