<?php

namespace bizley\tests;

use Lcobucci\JWT\Signer\Hmac\Sha512;

class HS512Test extends SignerTestCase
{
    public function getSigner(): Sha512
    {
        return new Sha512();
    }
}
