<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Providers\Auth;


use Kangst\JWTAuth\Contracts\Providers\Authenticatable;
use Kangst\JWTAuth\Contracts\Providers\UserProvider;
use Kangst\JWTAuth\Exceptions\JWTGuardException;
use think\Config;
use think\helper\Str;
use think\Model;

class User implements UserProvider
{
    /**
     * The auth model.
     *
     * @var Model
     */
    protected $auth_model;

    /**
     * @var Config
     */
    protected $config;

    /**
     * User constructor.
     *
     * @param null   $guard
     * @param Config $config
     * @throws JWTGuardException
     */
    public function __construct($guard = null, Config $config)
    {
        $this->config = $config;
        $this->setAuthModel($guard);
    }

    /**
     * setAuthModel
     *
     * @param string|null $guard
     * @return $this
     * @throws JWTGuardException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 16:34:47
     */
    public function setAuthModel(string $guard = null)
    {
        $guard_provider = 'jwt.guards.'. (empty($guard) ? 'default' : $guard) .'.provider';
        if ($this->config->has($guard_provider) && class_exists($model_class = $this->config->get($guard_provider))) {
            $this->auth_model = new $model_class();
        }

        // 效验 guard model class
        if (empty($this->auth_model) || !$this->auth_model instanceof Model) {
            throw new JWTGuardException('Undefined validation model');
        }

        return $this;
    }

    /**
     * retrieveById
     *
     * @param mixed $identifier
     * @return Authenticatable|GenericUser|null
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 16:02:48
     */
    public function retrieveById($identifier)
    {
        $user = $this->auth_model::where('id', $identifier)->find();
        return $this->getGenericUser($user ? $user->toArray() : array());
    }

    /**
     * retrieveByToken
     *
     * @param mixed  $identifier
     * @param string $token
     * @return Authenticatable|GenericUser|null
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 16:03:43
     */
    public function retrieveByToken($identifier, $token)
    {
        $find = $this->auth_model::where('id', $identifier)->find();
        $user = $this->getGenericUser($find ? $find->toArray() : array());

        return $user && $user->getRememberToken() && hash_equals($user->getRememberToken(), $token)
            ? $user : null;
    }

    /**
     * updateRememberToken
     *
     * @param Authenticatable $user
     * @param string          $token
     * @throws \think\Exception
     * @throws \think\exception\PDOException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 16:04:30
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        $this->auth_model
            ->where($user->getAuthIdentifierName(), $user->getAuthIdentifier())
            ->update([$user->getRememberTokenName() => $token]);
    }

    /**
     * retrieveByCredentials
     *
     * @param array $credentials
     * @return Authenticatable|GenericUser|void|null
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:35:46
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials) || (count($credentials) === 1 && array_key_exists('password', $credentials))) {
            return;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // generic "user" object that will be utilized by the Guard instances.
        $query = $this->auth_model;

        foreach ($credentials as $key => $value) {
            if (! Str::contains($key, 'password')) {
                $query->where($key, $value);
            }
        }

        // Now we are ready to execute the query to see if we have an user matching
        // the given credentials. If not, we will just return nulls and indicate
        // that there are no matching users for these given credential arrays.
        $user = $query->find();

        return $this->getGenericUser($user ? $user->toArray() : array());
    }

    /**
     * validateCredentials
     *
     * @param Authenticatable $user
     * @param array           $credentials
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-17 00:12:44
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        foreach ($credentials as $key => $value) {
            if ((!isset($user->$key) || $user->$key != $value) 
                && strtolower($key) != strtolower($user->getAuthPasswordName())
            ) {
                return false;
            }

            if (strtolower($key) === strtolower($user->getAuthPasswordName())
                && !password_verify($credentials[$key], $user->getAuthPassword())
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * getGenericUser
     *
     * @param $user
     * @return GenericUser
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 15:58:48
     */
    protected function getGenericUser($user)
    {
        if(!is_null($user)) {
            return new GenericUser($user);
        }
    }
}