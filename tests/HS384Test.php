<?php declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha384;

class HS384Test extends SignerTestCase
{
    public function getSigner(): Signer
    {
        return new Sha384();
    }
}
