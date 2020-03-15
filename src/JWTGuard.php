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


use Kangst\JWTAuth\Contracts\JWTSubjectInterface;
use Kangst\JWTAuth\Contracts\Providers\Authenticatable;
use Kangst\JWTAuth\Contracts\Providers\Guard;
use Kangst\JWTAuth\Contracts\Providers\UserProvider;
use Kangst\JWTAuth\Exceptions\JWTException;
use Kangst\JWTAuth\Exceptions\UserNotDefinedException;
use Kangst\JWTAuth\Support\GuardHelpers;
use Kangst\JWTAuth\Support\Macroable;
use think\Request;

class JWTGuard implements Guard
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Kangst\JWTAuth\Contracts\Providers\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The JWT instance.
     *
     * @var \Kangst\JWTAuth\JWT
     */
    protected $jwt;

    /**
     * The request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * Instantiate the class.
     *
     * @param  \Kangst\JWTAuth\JWT  $jwt
     * @param  UserProvider  $provider
     * @param  Request  $request
     *
     * @return void
     */
    public function __construct(JWT $jwt, UserProvider $provider, Request $request)
    {
        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Kangst\JWTAuth\Contracts\Providers\Authenticatable|null
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->jwt->setRequest($this->request)->getToken() &&
            ($payload = $this->jwt->check(true)) &&
            $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @return \Kangst\JWTAuth\Contracts\Providers\Authenticatable
     * @throws Exceptions\TokenBlacklistedException
     * @throws \Kangst\JWTAuth\Exceptions\UserNotDefinedException
     * @throws JWTException
     */
    public function userOrFail()
    {
        if (! $user = $this->user()) {
            throw new UserNotDefinedException();
        }

        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     * @throws Exceptions\TokenInvalidException
     */
    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @param array $credentials
     * @param bool  $login
     * @return bool|string
     * @throws Exceptions\TokenInvalidException
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    /**
     * Create a token for a user.
     *
     * @param \Kangst\JWTAuth\Contracts\JWTSubjectInterface $user
     * @return string
     * @throws Exceptions\TokenInvalidException
     */
    public function login(JWTSubjectInterface $user)
    {
        $token = $this->jwt->fromUser($user);
        $this->setToken($token)->setUser($user);

        return $token;
    }

    /**
     * Logout the user, thus invalidating the token.
     *
     * @param bool $forceForever
     * @return void
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     *
     * @param bool $forceForever
     * @param bool $resetClaims
     * @return string
     * @throws Exceptions\TokenBlacklistedException
     * @throws Exceptions\TokenInvalidException
     * @throws JWTException
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    /**
     * Invalidate the token.
     *
     * @param bool $forceForever
     * @return JWT
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function invalidate($forceForever = false)
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    /**
     * Create a new token by User id.
     *
     * @param mixed $id
     * @return string|null
     * @throws Exceptions\TokenInvalidException
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            return $this->jwt->fromUser($user);
        }
    }

    /**
     * Log a user into the application using their credentials.
     *
     * @param array $credentials
     * @return bool
     * @throws Exceptions\TokenInvalidException
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given User into the application.
     *
     * @param  mixed  $id
     *
     * @return bool
     */
    public function onceUsingId($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Alias for onceUsingId.
     *
     * @param  mixed  $id
     *
     * @return bool
     */
    public function byId($id)
    {
        return $this->onceUsingId($id);
    }

    /**
     * Add any custom claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function claims(array $claims)
    {
        $this->jwt->claims($claims);

        return $this;
    }

    /**
     * Get the raw Payload instance.
     *
     * @return Payload
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function getPayload()
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Alias for getPayload().
     *
     * @return Payload
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Set the token.
     *
     * @param Token|string $token
     * @return $this
     * @throws Exceptions\TokenInvalidException
     */
    public function setToken($token)
    {
        $this->jwt->setToken($token);

        return $this;
    }

    /**
     * Set the token ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->jwt->factory()->setTTL($ttl);

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @return UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param  UserProvider  $provider
     *
     * @return $this
     */
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    /**
     * Return the currently cached user.
     *
     * @return Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return Request
     */
    public function getRequest()
    {
        return $this->request ?: new Request();
    }

    /**
     * Set the current request instance.
     *
     * @param  Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return Authenticatable
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Ensure the JWTSubject matches what is in the token.
     *
     * @return  bool
     * @throws Exceptions\JWTException
     * @throws Exceptions\TokenBlacklistedException
     */
    protected function validateSubject()
    {
        // If the provider doesn't have the necessary method
        // to get the underlying model name then allow.
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        return $this->jwt->checkSubjectModel($this->provider->getModel());
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @throws JWTException
     *
     * @return JWT
     */
    protected function requireToken()
    {
        if (! $this->jwt->setRequest($this->getRequest())->getToken()) {
            throw new JWTException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    /**
     * Magically call the JWT instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new \BadMethodCallException("Method [$method] does not exist.");
    }
}