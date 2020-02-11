<?php


namespace Kangst\JWTAuth\Validators;


use Kangst\JWTAuth\Exceptions\TokenInvalidException;

class TokenValidator extends ValidatorAbstract
{
    /**
     * Check the structure of the token.
     *
     * @param string $value
     * @return string
     * @throws TokenInvalidException
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-10 12:32:37
     */
    public function check($value)
    {
        return $this->validateStructure($value);
    }

    /**
     * Validate Structure
     *
     * @param string $token
     * @return string
     * @throws TokenInvalidException
     * @author Kang Shutian <kst157521@163.com>
     * @date 2020-02-10 12:31:58
     */
    protected function validateStructure($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));
        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new TokenInvalidException('Malformed token');
        }

        return $token;
    }
}