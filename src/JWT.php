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


use Kangst\JWTAuth\Contracts\Providers\Authenticatable;
use Kangst\JWTAuth\Exceptions\JWTException;
use Kangst\JWTAuth\Http\Parser\Parser;
use Kangst\JWTAuth\Providers\Auth\GenericUser;
use Kangst\JWTAuth\Support\CustomClaims;
use think\Request;

class JWT
{
    use CustomClaims;

    /**
     * @var Manager
     */
    protected $manager;

    /**
     * @var Parser
     */
    protected $parser;

    /**
     * @var Token|null
     */
    protected $token;

    /**
     * Lock the subject.
     *
     * @var bool
     */
    protected $lockSubject = true;

    /**
     * JWT constructor.
     *
     * @param Manager $manager
     * @param Parser  $parser
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     *
     * @param GenericUser $subject
     * @return string
     * @throws Exceptions\TokenInvalidException
     * @throws JWTException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:41:08
     */
    public function fromSubject(GenericUser $subject)
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     *
     * @param GenericUser $user
     * @return string
     * @throws Exceptions\TokenInvalidException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:40:46
     */
    public function fromUser(GenericUser $user)
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     *
     * @param bool $forceForever
     * @param bool $resetClaims
     * @return string
     * @throws Exceptions\JWTException
     * @throws Exceptions\TokenBlacklistedException
     * @throws Exceptions\TokenInvalidException
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
            ->refresh($this->token, $forceForever, $resetClaims)
            ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @param bool $forceForever
     * @return $this
     * @throws Exceptions\JWTException
     * @throws Exceptions\TokenBlacklistedException
     */
    public function invalidate($forceForever = false)
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @return Payload
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param bool $getPayload
     * @return Payload|bool
     * @throws Exceptions\TokenBlacklistedException
     */
    public function check($getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     *
     * @return Token|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (JWTException $e) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @return $this
     * @throws JWTException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 23:11:54
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
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
        $this->requireToken();

        return $this->manager->decode($this->token);
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
     * Convenience method to get a claim value.
     *
     * @param string $claim
     * @return mixed
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function getClaim($claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     *
     * @param GenericUser $subject
     * @return Payload
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:41:26
     */
    public function makePayload(GenericUser $subject)
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param GenericUser $subject
     * @return array
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:41:41
     */
    protected function getClaimsArray(GenericUser $subject)
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getAuthCustomClaims(), // custom claims from GenericUser method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @param GenericUser|Authenticatable $subject
     * @return array
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:41:58
     */
    protected function getClaimsForSubject(GenericUser $subject)
    {
        return array_merge([
            'sub' => $subject->getAuthIdentifierName(),
        ], $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []);
    }

    /**
     * Hash the subject model and return it.
     *
     * @param  string|object  $model
     *
     * @return string
     */
    protected function hashSubjectModel($model)
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param string|object $model
     * @return bool
     * @throws Exceptions\TokenBlacklistedException
     * @throws JWTException
     */
    public function checkSubjectModel($model)
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
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
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @return void
     * @throws JWTException
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JWTException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @param Request $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set whether the subject should be "locked".
     *
     * @param  bool  $lock
     *
     * @return $this
     */
    public function lockSubject($lock)
    {
        $this->lockSubject = $lock;

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return Manager
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 23:15:13
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return Parser
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 23:15:27
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return Factory
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 23:15:36
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return Blacklist
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 23:15:47
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
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
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new \BadMethodCallException("Method [$method] does not exist.");
    }
}
