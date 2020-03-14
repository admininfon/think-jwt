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


use Kangst\JWTAuth\Claims\ClaimInterface;
use Kangst\JWTAuth\Claims\Collection;
use Kangst\JWTAuth\Exceptions\PayloadException;
use Kangst\JWTAuth\Validators\PayloadValidator;
use think\contract\Arrayable;
use think\contract\Jsonable;
use think\helper\Arr;

class Payload implements \ArrayAccess, Arrayable,\Countable, Jsonable, \JsonSerializable
{
    /**
     * The collection of claims.
     *
     * @var \Kangst\JWTAuth\Claims\Collection
     */
    private $claims;

    /**
     * Payload constructor.
     *
     * @param Collection       $claims
     * @param PayloadValidator $validator
     * @param bool             $refreshFlow
     */
    public function __construct(Collection $claims, PayloadValidator $validator, $refreshFlow = false)
    {
        try {
            $this->claims = $validator->setRefreshFlow($refreshFlow)->check((array)$claims);
        } catch (Exceptions\TokenExpiredException $e) {

        } catch (Exceptions\TokenInvalidException $e) {

        }
    }

    /**
     * getClaims
     *
     * @return Collection
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:42:58
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Checks if a payload matches some expected values.
     *
     * @param  array  $values
     * @param  bool  $strict
     *
     * @return bool
     */
    public function matches(array $values, $strict = false)
    {
        if (empty($values)) {
            return false;
        }

        $claims = $this->getClaims();

        foreach ($values as $key => $value) {
            if (! $claims->has($key) || ! $claims->get($key)->matches($value, $strict)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if a payload strictly matches some expected values.
     *
     * @param  array  $values
     *
     * @return bool
     */
    public function matchesStrict(array $values)
    {
        return $this->matches($values, true);
    }

    /**
     * Get the payload.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        $claim = value($claim);

        if ($claim !== null) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return Arr::get($this->toArray(), $claim);
        }

        return $this->toArray();
    }

    /**
     * Get the underlying Claim instance.
     *
     * @param string $claim
     * @return Claims\ClaimInterface
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:48:46
     */
    public function getInternal($claim)
    {
        return $this->claims->getByClaimName($claim);
    }

    /**
     * Determine whether the payload has the claim (by instance).
     *
     * @param ClaimInterface $claim
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:50:11
     */
    public function has(ClaimInterface $claim)
    {
        return $this->claims->has($claim->getName());
    }

    /**
     * hasKey
     *
     * @param $claim
     * @return bool
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:43:38
     */
    public function hasKey($claim)
    {
        return $this->offsetExists($claim);
    }

    /**
     * Get the array of claims.
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->claims->toPlainArray();
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param  mixed  $key
     *
     * @return bool
     */
    public function offsetExists($key)
    {
        return Arr::has($this->toArray(), $key);
    }

    /**
     * Get an item at a given offset.
     *
     * @param  mixed  $key
     *
     * @return mixed
     */
    public function offsetGet($key)
    {
        return Arr::get($this->toArray(), $key);
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param mixed $key
     * @param mixed $value
     * @throws PayloadException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:55:02
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param mixed $key
     * @throws PayloadException
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-14 21:56:09
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims.
     *
     * @return int
     */
    public function count()
    {
        return count($this->toArray());
    }

    /**
     * Invoke the Payload as a callable function.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function __invoke($claim = null)
    {
        return $this->get($claim);
    }

    /**
     * Get the payload as JSON.
     *
     * @param  int  $options
     *
     * @return string
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson();
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Magically get a claim value.
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
        if (preg_match('/get(.+)\b/i', $method, $matches)) {
            foreach ($this->claims as $claim) {
                if (get_class($claim) === 'Kangst\\JWTAuth\\Claims\\'.$matches[1]) {
                    return $claim->getValue();
                }
            }
        }

        throw new \BadMethodCallException(sprintf('The claim [%s] does not exist on the payload.', $method));
    }
}