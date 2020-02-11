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


use Kangst\JWTAuth\Validators\TokenValidator;

class Token
{
    /**
     * @var string
     */
    private $value;

    /**
     * Token constructor.
     * @param string $value
     * @throws Exceptions\TokenInvalidException
     */
    public function __construct($value)
    {
        $this->value = (string) (new TokenValidator())->check($value);
    }

    /**
     * get
     *
     * @return string
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-10 12:37:17
     */
    public function get()
    {
        return $this->value;
    }

    /**
     * Get the token when casting to string.
     *
     * @return string
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-10 12:37:48
     */
    public function __toString()
    {
        return $this->get();
    }
}
