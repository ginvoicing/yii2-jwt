<?php declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha512;

class HS512Test extends SignerTestCase
{
    public function getSigner(): Signer
    {
        return new Sha512();
    }
}
