<?php


namespace Kangst\JWTAuth;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parsing\Encoder;

class JWT extends Builder
{
    public function __construct(Encoder $encoder = null, ClaimFactory $claimFactory = null)
    {
        parent::__construct($encoder, $claimFactory);
    }
}
