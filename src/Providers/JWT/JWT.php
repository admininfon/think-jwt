<?php
/*
 * This file is part of kkm_mbc.
 *
 * (c) Kang Shutian <kst157521@163.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kangst\JWTAuth\Providers\JWT;


use Kangst\JWTAuth\Exceptions\SignatureInvalidException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Namshi\JOSE\JWS;
use think\Config;

class JWT
{
    const LCOBUCCI = 'lcobucci';
    const NAMSHI = 'namshi';

    /**
     * signer provider
     *
     * @var Lcobucci|Namshi
     */
    private $provider;

    public function __construct($provider = self::LCOBUCCI, Builder $builder, Parser $parser, JWS $jws, Config $config)
    {
        $secret = $config->get('jwt.secret');
        $algo = $config->get('jwt.algo');
        $keys = $config->get('jwt.keys');

        switch ($provider) {
            case self::LCOBUCCI:
                $this->provider = new Lcobucci($builder, $parser, $secret, $algo, $keys);
                break;

            case self::NAMSHI:
                $this->provider = new Namshi($jws, $secret, $algo, $keys);
                break;

            default:
                throw new SignatureInvalidException('Invalid signature class.');
        }
    }

    /**
     * getProvider
     *
     * @return Lcobucci|Namshi
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-15 22:55:43
     */
    public function getProvider()
    {
        return $this->provider;
    }
}