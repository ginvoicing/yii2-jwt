<?php

namespace bizley\tests;

use Lcobucci\JWT\Signer\Hmac\Sha256;

class HS256Test extends SignerTestCase
{
    public function getSigner(): Sha256
    {
        return new Sha256();
    }
}
