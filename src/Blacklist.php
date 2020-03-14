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


use Kangst\JWTAuth\Contracts\Providers\Storage;
use Kangst\JWTAuth\Support\Utils;

class Blacklist
{
    /**
     * The storage.
     *
     * @var \Kangst\JWTAuth\Contracts\Providers\Storage
     */
    protected $storage;

    /**
     * The grace period when a token is blacklisted. In seconds.
     *
     * @var int
     */
    protected $gracePeriod = 0;

    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * The unique key held within the blacklist.
     *
     * @var string
     */
    protected $key = 'jti';

    /**
     * constructor.
     *
     * @param \Kangst\JWTAuth\Contracts\Providers\Storage $storage
     * @return void
     */
    public function __construct(Storage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     *
     * @param Payload $payload
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:34:00
     */
    public function add(Payload $payload)
    {
        // if there is no exp claim then add the jwt to
        // the blacklist indefinitely
        if (! $payload->hasKey('exp')) {
            return $this->addForever($payload);
        }

        // if we have already added this token to the blacklist
        if (! empty($this->storage->get($this->getKey($payload)))) {
            return true;
        }

        $this->storage->add(
            $this->getKey($payload),
            ['valid_until' => $this->getGraceTimestamp()],
            $this->getMinutesUntilExpired($payload)
        );

        return true;
    }

    /**
     * Add the token (jti claim) to the blacklist indefinitely.
     *
     * @param \Kangst\JWTAuth\Payload $payload
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 19:16:21
     */
    public function addForever(Payload $payload)
    {
        $this->storage->forever($this->getKey($payload), 'forever');

        return true;
    }

    /**
     * Get the unique key held within the blacklist.
     *
     * @param Payload $payload
     * @return mixed
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:28:58
     */
    public function getKey(Payload $payload)
    {
        return $payload($this->key);
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     *
     * @return int
     */
    protected function getGraceTimestamp()
    {
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    /**
     * Get the number of minutes until the token expiry.
     *
     * @param Payload $payload
     * @return int
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:32:49
     */
    protected function getMinutesUntilExpired(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);
        $iat = Utils::timestamp($payload['iat']);

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        return $exp->max($iat->addMinutes($this->refreshTTL))->addMinute()->diffInRealMinutes();
    }

    /**
     * Determine whether the token has been blacklisted.
     *
     * @param Payload $payload
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:35:16
     */
    public function has(Payload $payload)
    {
        $val = $this->storage->get($this->getKey($payload));

        // exit early if the token was blacklisted forever,
        if ($val === 'forever') {
            return true;
        }

        // check whether the expiry + grace has past
        return ! empty($val) && ! Utils::isFuture($val['valid_until']);
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     *
     * @param Payload $payload
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:36:11
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($this->getKey($payload));
    }

    /**
     * Remove all tokens from the blacklist.
     *
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:36:55
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Set the grace period.
     *
     * @param $gracePeriod
     * @return $this
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:38:10
     */
    public function setGracePeriod($gracePeriod)
    {
        $this->gracePeriod = (int) $gracePeriod;

        return $this;
    }

    /**
     * Get the grace period.
     *
     * @return int
     */
    public function getGracePeriod()
    {
        return $this->gracePeriod;
    }

    /**
     * Set the unique key held within the blacklist.
     *
     * @param  string  $key
     *
     * @return $this
     */
    public function setKey($key)
    {
        $this->key = value($key);

        return $this;
    }

    /**
     * Set the refresh time limit.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = (int) $ttl;

        return $this;
    }

    /**
     * Get the refresh time limit.
     *
     * @return int
     */
    public function getRefreshTTL()
    {
        return $this->refreshTTL;
    }
}