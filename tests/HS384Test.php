<?php

namespace bizley\tests;

use Lcobucci\JWT\Signer\Hmac\Sha384;

class HS384Test extends SignerTestCase
{
    public function getSigner(): Sha384
    {
        return new Sha384();
    }
}
