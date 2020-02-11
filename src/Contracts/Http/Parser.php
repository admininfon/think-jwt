<?php
/*
 * This file is part of Parser.php.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Contracts\Http;


use think\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @param Request $request
     * @return null|string
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-11 16:00:50
     */
    public function parse(Request $request);
}