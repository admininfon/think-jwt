<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Claims;


class Issuer extends ClaimInterface
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'iss';
}