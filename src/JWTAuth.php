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


use Kangst\JWTAuth\Http\Parser\Parser;
use Kangst\JWTAuth\Providers\Auth\Auth;

class JWTAuth extends JWT
{
    /**
     * The authentication provider.
     *
     * @var Auth
     */
    protected $auth;

    /**
     * JWTAuth constructor.
     *
     * @param Manager $manager
     * @param Auth    $auth
     * @param Parser  $parser
     */
    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param array $credentials
     * @return false|string
     * @throws Exceptions\TokenInvalidException
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \Kangst\JWTAuth\Contracts\JWTSubjectInterface|false
     * @throws Exceptions\JWTException
     * @throws Exceptions\TokenBlacklistedException
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \Kangst\JWTAuth\Contracts\JWTSubjectInterface|false
     * @throws Exceptions\JWTException
     * @throws Exceptions\TokenBlacklistedException
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     *
     * @return \Kangst\JWTAuth\Contracts\JWTSubjectInterface
     */
    public function user()
    {
        return $this->auth->user();
    }

}