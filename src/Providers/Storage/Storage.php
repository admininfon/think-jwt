<?php
/*
 * This file is part of Storage.php.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Providers\Storage;


use Kangst\JWTAuth\Contracts\Providers\Storage as StorageInterface;
use think\Cache;

class Storage extends Provider implements StorageInterface
{
    /**
     * @var Cache
     */
    protected $cache;

    /**
     * The used cache tag.
     *
     * @var string
     */
    protected $tag = 'kangst.jwt';

    /**
     * @var bool
     */
    protected $supportsTags;

    /**
     * Storage constructor.
     *
     * @param Cache $cache
     */
    public function __construct(Cache $cache)
    {
        $this->cache = $cache;
    }

    /**
     * add
     *
     * @param string $key
     * @param mixed  $value
     * @param int    $minutes
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:13:04
     */
    public function add($key, $value, $minutes)
    {
        $this->cache()->set($key, $value, is_int($minutes) ? ($minutes * 60) : 0);
    }

    /**
     * forever
     *
     * @param string $key
     * @param mixed  $value
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:14:42
     */
    public function forever($key, $value)
    {
        $this->add($key, $value, 0);
    }

    /**
     * get
     *
     * @param string $key
     * @return mixed
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:15:20
     */
    public function get($key)
    {
        return $this->cache()->get($key);
    }

    /**
     * destroy
     *
     * @param string $key
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:16:46
     */
    public function destroy($key)
    {
        return $this->cache()->rm($key);
    }

    /**
     * flush
     *
     * @return bool|void
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:18:00
     */
    public function flush()
    {
        return $this->cache()->clear();
    }

    /**
     * cache
     *
     * @return Cache
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:09:28
     */
    protected function cache()
    {
        if ($this->supportsTags === null) {
            $this->determineTagSupport();
        }

        if ($this->supportsTags) {
            return $this->cache->tag($this->tag);
        }

        return $this->cache;
    }

    /**
     * determineTagSupport
     *
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-16 14:09:01
     */
    protected function determineTagSupport()
    {
        if (method_exists($this->cache, 'tag') || $this->cache instanceof Cache) {
            $this->cache->tag($this->tag);
            $this->supportsTags = true;
        } else {
            $this->supportsTags = false;
        }
    }
}