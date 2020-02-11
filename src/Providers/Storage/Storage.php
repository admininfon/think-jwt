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

class Storage extends Provider implements StorageInterface
{

    /**
     * @inheritDoc
     */
    public function add($key, $value, $minutes)
    {
        // TODO: Implement add() method.
    }

    /**
     * @inheritDoc
     */
    public function forever($key, $value)
    {
        // TODO: Implement forever() method.
    }

    /**
     * @inheritDoc
     */
    public function get($key)
    {
        // TODO: Implement get() method.
    }

    /**
     * @inheritDoc
     */
    public function destroy($key)
    {
        // TODO: Implement destroy() method.
    }

    /**
     * @inheritDoc
     */
    public function flush()
    {
        // TODO: Implement flush() method.
    }
}