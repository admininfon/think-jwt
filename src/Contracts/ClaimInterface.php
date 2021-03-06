<?php


namespace Kangst\JWTAuth\Contracts;


interface ClaimInterface
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param  mixed  $value
     *
     * @throws \Kangst\JWTAuth\Exceptions\InvalidClaimException
     *
     * @return $this
     */
    public function setValue($value);

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set the claim name.
     *
     * @param  string  $name
     *
     * @return $this
     */
    public function setName($name);

    /**
     * Get the claim name.
     *
     * @return string
     */
    public function getName();

    /**
     * Validate the Claims value.
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    public function validateCreate($value);
}
