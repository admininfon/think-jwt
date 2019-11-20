<?php


namespace Kangst\JWTAuth\Exceptions;


use Exception;

class JWTException extends Exception
{
    /**
     * {@inheritdoc}
     */
    protected $message = 'An error occurred';
}
