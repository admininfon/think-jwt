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


use Kangst\JWTAuth\Claims\Collection;
use Kangst\JWTAuth\Contracts\Providers\Authenticatable;

class GenericUser implements Authenticatable
{
    /**
     * All of the user's attributes.
     *
     * @var array
     */
    protected $attributes;

    /**
     * @var array|Collection
     */
    public $auth_user;

    /**
     * Create a new generic User object.
     *
     * @param  array|Collection  $attributes
     * @return void
     */
    public function __construct($attributes)
    {
        $this->auth_user = $attributes;
        $this->attributes = $attributes instanceof Collection ? $attributes->toArray() : $attributes;
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return $this->auth_user->getJWTIdentifier();
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        $name = $this->getAuthIdentifierName();

        return $this->attributes[$name];
    }

    /**
     * Get the password for the user.
     *
     * @return string
     */
    public function getAuthPassword()
    {
        return $this->attributes['password'];
    }

    /**
     * getAuthPasswordName
     *
     * @return string
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 23:44:56
     */
    public function getAuthPasswordName()
    {
        return 'password';
    }

    /**
     * Get the "remember me" token value.
     *
     * @return string
     */
    public function getRememberToken()
    {
        return $this->attributes[$this->getRememberTokenName()];
    }

    /**
     * Set the "remember me" token value.
     *
     * @param  string  $value
     * @return void
     */
    public function setRememberToken($value)
    {
        $this->attributes[$this->getRememberTokenName()] = $value;
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     */
    public function getRememberTokenName()
    {
        return 'remember_token';
    }

    /**
     * getAuthCustomClaims
     *
     * @return array
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-19 02:03:02
     */
    public function getAuthCustomClaims()
    {
        return $this->auth_user->getJWTCustomClaims();
    }

    /**
     * user
     *
     * @return array|Collection|null
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-19 18:02:44
     */
    public function user()
    {
        return $this->attributes ?? $this->auth_user;
    }

    /**
     * Dynamically access the user's attributes.
     *
     * @param  string  $key
     * @return mixed
     */
    public function __get($key)
    {
        return $this->attributes[$key];
    }

    /**
     * Dynamically set an attribute on the user.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    public function __set($key, $value)
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Dynamically check if a value is set on the user.
     *
     * @param  string  $key
     * @return bool
     */
    public function __isset($key)
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Dynamically unset a value on the user.
     *
     * @param  string  $key
     * @return void
     */
    public function __unset($key)
    {
        unset($this->attributes[$key]);
    }
}