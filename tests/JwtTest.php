<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use bizley\tests\stubs\JwtStub;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;
use stdClass;
use yii\base\InvalidConfigException;

class JwtTest extends TestCase
{
    public function testAvailableSigners(): void
    {
        self::assertSame(
            [
                Jwt::HS256 => [Signer\Hmac\Sha256::class],
                Jwt::HS384 => [Signer\Hmac\Sha384::class],
                Jwt::HS512 => [Signer\Hmac\Sha512::class],
                Jwt::RS256 => [Signer\Rsa\Sha256::class],
                Jwt::RS384 => [Signer\Rsa\Sha384::class],
                Jwt::RS512 => [Signer\Rsa\Sha512::class],
                Jwt::ES256 => [Signer\Ecdsa\Sha256::class],
                Jwt::ES384 => [Signer\Ecdsa\Sha384::class],
                Jwt::ES512 => [Signer\Ecdsa\Sha512::class],
                Jwt::EDDSA => [Signer\Eddsa::class],
            ],
            (new Jwt())->signers,
        );
    }

    public function testAvailableAlgorithmTypes(): void
    {
        self::assertSame(
            [
                Jwt::SYMMETRIC => [
                    Jwt::HS256,
                    Jwt::HS384,
                    Jwt::HS512,
                ],
                Jwt::ASYMMETRIC => [
                    Jwt::RS256,
                    Jwt::RS384,
                    Jwt::RS512,
                    Jwt::ES256,
                    Jwt::ES384,
                    Jwt::ES512,
                    Jwt::EDDSA,
                ],
            ],
            (new Jwt())->algorithmTypes,
        );
    }

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

    public function testValidateSuccessWithStringToken(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $config->signer(),
            $config->signingKey()
        )->toString();
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

    /**
     * @doesNotPerformAssertions
     */
    public function testAssertSuccessWithStringToken(): void
    {
        $jwt = new Jwt();
        $config = $jwt->getConfiguration();
        $config->setValidationConstraints(new IdentifiedBy('abc'));
        $token = $jwt->getBuilder()->identifiedBy('abc')->getToken(
            $config->signer(),
            $config->signingKey()
        )->toString();
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
            'empty' => ['', 'Empty string used as a key configuration!'],
            'object' => [new stdClass(), 'Invalid key configuration!'],
            'int value' => [[Jwt::KEY => 1], 'Invalid key value!'],
            'array value' => [[Jwt::KEY => []], 'Invalid key value!'],
            'object value' => [[Jwt::KEY => new stdClass()], 'Invalid key value!'],
            'store' => [[Jwt::STORE => ''], 'Invalid key store!'],
            'method' => [[Jwt::METHOD => ''], 'Invalid key method!'],
            'int pass' => [[Jwt::PASSPHRASE => 1], 'Invalid key passphrase!'],
            'array pass' => [[Jwt::PASSPHRASE => []], 'Invalid key passphrase!'],
            'object pass' => [[Jwt::PASSPHRASE => new stdClass()], 'Invalid key passphrase!'],
        ];
    }

    /**
     * @dataProvider providerForInvalidKey
     * @param mixed $key
     */
    public function testInvalidKey($key, string $message): void
    {
        $this->expectExceptionMessage($message);
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

    public function testMethodsVisibility(): void
    {
        $jwt = new Jwt();
        self::assertNotEmpty($jwt->getConfiguration());
        self::assertNotEmpty($jwt->getBuilder());
        self::assertNotEmpty($jwt->getParser());
    }

    public function providerForWrongKeyNames(): array
    {
        return [
            '@' => ['_@bizley/tests/data/rs256.key'],
            'file://' => ['_file://' . __DIR__ . '/data/rs256.key'],
        ];
    }

    /**
     * @dataProvider providerForWrongKeyNames
     * @throws InvalidConfigException
     */
    public function testWrongFileKeyNameStartingCharacters(string $key): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
        // name instead of file content
        self::assertSame($key, $jwt->getConfiguration()->signingKey()->contents());
    }

    public function providerForRightKeyNames(): array
    {
        return [
            '@' => ['@bizley/tests/data/rs256.key'],
            'file://' => ['file://' . __DIR__ . '/data/rs256.key'],
        ];
    }

    /**
     * @dataProvider providerForRightKeyNames
     * @throws InvalidConfigException
     */
    public function testRightFileKeyNameStartingCharacters(string $key): void
    {
        $jwt = new Jwt(
            [
                'signer' => Jwt::HS256,
                'signingKey' => $key
            ]
        );
        // content instead of file name
        self::assertSame(
            '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
',
            $jwt->getConfiguration()->signingKey()->contents()
        );
    }

    public function providerForSignerSignatureConverter(): array
    {
        return [
            Jwt::ES256 => [Jwt::ES256],
            Jwt::ES384 => [Jwt::ES384],
            Jwt::ES512 => [Jwt::ES512],
        ];
    }

    /**
     * @dataProvider providerForSignerSignatureConverter
     */
    public function testPrepareSignatureConverter(string $signerId): void
    {
        new Jwt(['signer' => $signerId, 'signingKey' => ' ', 'verifyingKey' => ' ']);
        $this->assertInstanceOf(
            Signer\Ecdsa\MultibyteStringConverter::class,
            \Yii::$container->get(Signer\Ecdsa\SignatureConverter::class)
        );
    }
}
