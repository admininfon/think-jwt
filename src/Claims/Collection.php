<?php
/*
 * This file is part of think-jwt.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Claims;


use think\Collection as ThinkCollection;

class Collection extends ThinkCollection
{
    /**
     * Create a new collection.
     *
     * @param mixed $items
     *
     * @return void
     */
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     *
     * @param string $name
     * @param callable $callback
     * @param mixed $default
     *
     * @return \Kangst\JWTAuth\Claims\ClaimInterface
     */
    public function getByClaimName($name, callable $callback = null, $default = null)
    {
        return $this->filter(function (ClaimInterface $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim under a given context.
     *
     * @param string $context
     *
     * @return $this
     */
    public function validate($context = 'payload')
    {
        $args = func_get_args();
        array_shift($args);

        $this->each(function ($claim) use ($context, $args) {
            call_user_func_array(
                [$claim, 'validate' . ucfirst($context)],
                $args
            );
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     *
     * @param  mixed  $claims
     *
     * @return bool
     */
    public function hasAllClaims($claims)
    {
        return count($claims) && (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     *
     * @return array
     */
    public function toPlainArray()
    {
        return $this->map(function (ClaimInterface $claim) {
            return $claim->getValue();
        })->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items)
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     *
     * @param mixed $items
     *
     * @return array
     */
    private function sanitizeClaims($items)
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (!is_string($key) && $value instanceof ClaimInterface) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }

    /**
     * Determine if an item exists in the collection by key.
     *
     * @param  mixed  $key
     * @return bool
     */
    public function has($key)
    {
        $keys = is_array($key) ? $key : func_get_args();

        foreach ($keys as $value) {
            if (! $this->offsetExists($value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get an item from the collection by key.
     *
     * @param  mixed  $key
     * @param  mixed  $default
     * @return mixed
     */
    public function get($key, $default = null)
    {
        if ($this->offsetExists($key)) {
            return $this->items[$key];
        }

        return value($default);
    }

    /**
     * map
     *
     * @param callable $callback
     * @return $this|ThinkCollection
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-19 02:23:30
     */
    public function map(callable $callback)
    {
        $keys = array_keys($this->items);

        $items = array_map($callback, $this->items, $keys);

        return new static(array_combine($keys, $items));
    }

    /**
     * keys
     *
     * @return $this|array|ThinkCollection
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-19 17:37:10
     */
    public function keys()
    {
        return new static(array_keys($this->items));
    }
}
