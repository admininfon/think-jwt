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


use Kangst\JWTAuth\Contracts\Providers\Auth;
use Kangst\JWTAuth\Http\Parser\Parser;

class JWTAuth extends JWT
{
    /**
     * The authentication provider.
     *
     * @var \Kangst\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Constructor.
     *
     * @param  \Kangst\JWTAuth\Manager  $manager
     * @param  \Kangst\JWTAuth\Contracts\Providers\Auth  $auth
     * @param  \Kangst\JWTAuth\Http\Parser\Parser  $parser
     *
     * @return void
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