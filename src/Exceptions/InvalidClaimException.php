<?php


namespace Kangst\JWTAuth\Exceptions;


use Kangst\JWTAuth\Claims\ClaimInterface;

class InvalidClaimException extends JWTException
{
    /**
     * Constructor.
     *
     * @param  \Kangst\JWTAuth\Claims\ClaimInterface  $claim
     * @param  int  $code
     * @param  \Exception|null  $previous
     *
     * @return void
     */
    public function __construct(ClaimInterface $claim, $code = 0, \Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim ['.$claim->getName().']', $code, $previous);
    }
}
