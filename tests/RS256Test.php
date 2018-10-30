<?php declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class RS256Test extends SignerTestCase
{
    public $jwtConfig = ['key' => '@bizley/tests/data/rsa256.pub'];

    private $key = '@bizley/tests/data/rsa256';

    public function getSigner(): Signer
    {
        return new Sha256();
    }
}
