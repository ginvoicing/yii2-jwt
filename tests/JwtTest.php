<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use bizley\tests\stubs\JwtStub;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;
use stdClass;
use yii\base\InvalidConfigException;

class JwtTest extends TestCase
{
    public function testNoInit(): void
    {
        $this->expectException(InvalidConfigException::class);
        $jwtStub = new JwtStub();
        $jwtStub->getConfiguration();
    }

    public function testValidateSuccess(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        self::assertTrue($jwt->validate($token));
    }

    public function testValidateFail(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken($config->signer(), $config->signingKey());
        self::assertFalse($jwt->validate($token));
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testAssertSuccess(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken($config->signer(), $config->signingKey());
        $jwt->assert($token);
    }

    public function testAssertFail(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('def')->getToken($config->signer(), $config->signingKey());
        $this->expectException(RequiredConstraintsViolated::class);
        $jwt->assert($token);
    }

    public function providerForInvalidKey(): array
    {
        return [
            'object' => [new stdClass()],
            'int value' => [[Jwt::KEY => 1]],
            'array value' => [[Jwt::KEY => []]],
            'object value' => [[Jwt::KEY => new stdClass()]],
            'store' => [[Jwt::STORE => '']],
            'method' => [[Jwt::METHOD => '']],
            'int pass' => [[Jwt::PASSPHRASE => 1]],
            'array pass' => [[Jwt::PASSPHRASE => []]],
            'object pass' => [[Jwt::PASSPHRASE => new stdClass()]],
        ];
    }

    /**
     * @dataProvider providerForInvalidKey
     * @param mixed $key
     */
    public function testInvalidKey($key): void
    {
        $this->expectException(InvalidConfigException::class);
        new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
    }

    public function testCustomEncoder(): void
    {
        $encoder = $this->createMock(Encoder::class);
        $encoder->expects(self::exactly(3))->method('base64UrlEncode');

        $jwt = new Jwt(['encoder' => $encoder]);
        $jwt->getBuilder()->getToken($jwt->getConfiguration()->signer(), $jwt->getConfiguration()->signingKey());
    }

    public function testCustomDecoder(): void
    {
        $decoder = $this->createMock(Decoder::class);
        $decoder->method('jsonDecode')->willReturn([]);
        $decoder->expects(self::exactly(2))->method('base64UrlDecode');

        $jwt = new Jwt(['decoder' => $decoder]);
        $jwt->parse(
            $jwt->getBuilder()->getToken(
                $jwt->getConfiguration()->signer(),
                $jwt->getConfiguration()->signingKey()
            )->toString()
        );
    }
}
