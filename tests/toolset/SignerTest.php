<?php

declare(strict_types=1);

namespace bizley\tests\toolset;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

#[CoversClass(Jwt::class)]
#[CoversClass(JwtTools::class)]
class SignerTest extends TestCase
{
    /**
     * @throws InvalidConfigException
     */
    public function getJwt(array $config = []): JwtTools
    {
        /** @var JwtTools $jwt */
        $jwt = \Yii::createObject(
            array_merge(
                ['class' => JwtTools::class],
                $config
            )
        );

        return $jwt;
    }

    public static function providerForSigners(): iterable
    {
        yield 'Direct signer provided' => [
            new Sha256(),
            'secret1secret1secret1secret1secret1secret1',
            null,
            Jwt::HS256
        ];
        yield 'Direct key provided' => [
            Jwt::HS256,
            InMemory::plainText('secret1secret1secret1secret1secret1secret1'),
            null,
            Jwt::HS256
        ];
        yield 'HS256' => [
            Jwt::HS256,
            'secret1secret1secret1secret1secret1secret1',
            null,
            Jwt::HS256
        ];
        yield 'HS256 base64' => [
            Jwt::HS256,
            [
                Jwt::KEY => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0MXNlY3JldDFzZWNyZXQx',
                Jwt::METHOD => JWT::METHOD_BASE64
            ],
            null,
            Jwt::HS256
        ];
        yield 'HS384' => [
            Jwt::HS384,
            'secret1secret1secret1secret1secret1secret1secret1',
            null,
            Jwt::HS384
        ];
        yield 'HS512' => [
            Jwt::HS512,
            'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
            null,
            Jwt::HS512
        ];
        yield 'HS256 pass' => [
            Jwt::HS256,
            [
                Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
                Jwt::PASSPHRASE => 'passphrase'
            ],
            null,
            Jwt::HS256
        ];
        yield 'HS384 pass' => [
            Jwt::HS384,
            [
                Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
                Jwt::PASSPHRASE => 'passphrase'
            ],
            null,
            Jwt::HS384
        ];
        yield 'HS512 pass' => [
            Jwt::HS512,
            [
                Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
                Jwt::PASSPHRASE => 'passphrase'
            ],
            null,
            Jwt::HS512
        ];
        yield 'RS256' => [
            Jwt::RS256,
            '@bizley/tests/data/rs256.key',
            '@bizley/tests/data/rs256.key.pub',
            Jwt::RS256
        ];
        yield 'RS256 with file handler' => [
            Jwt::RS256,
            'file://' . __DIR__ . '/../data/rs256.key',
            'file://' . __DIR__ . '/../data/rs256.key.pub',
            Jwt::RS256
        ];
        yield 'RS256 with in-memory file' => [
            Jwt::RS256,
            [
                Jwt::KEY => 'file://' . __DIR__ . '/../data/rs256.key',
                Jwt::METHOD => Jwt::METHOD_FILE,
            ],
            'file://' . __DIR__ . '/../data/rs256.key.pub',
            Jwt::RS256
        ];
        yield 'RS384' => [
            Jwt::RS384,
            '@bizley/tests/data/rs384.key',
            '@bizley/tests/data/rs384.key.pub',
            Jwt::RS384
        ];
        yield 'RS512' => [
            Jwt::RS512,
            '@bizley/tests/data/rs512.key',
            '@bizley/tests/data/rs512.key.pub',
            Jwt::RS512
        ];
        yield 'ES256' => [
            Jwt::ES256,
            '@bizley/tests/data/es256.key',
            '@bizley/tests/data/es256.key.pub',
            Jwt::ES256
        ];
        yield 'ES384' => [
            Jwt::ES384,
            '@bizley/tests/data/es384.key',
            '@bizley/tests/data/es384.key.pub',
            Jwt::ES384
        ];
        yield 'ES512' => [
            Jwt::ES512,
            '@bizley/tests/data/es512.key',
            '@bizley/tests/data/es512.key.pub',
            Jwt::ES512
        ];
    }

    #[DataProvider('providerForSigners')]
    public function testParseTokenWithSignature(
        string|object $signer,
        string|array|object $signingKey,
        string|array|null $verifyingKey,
        string $algorithm
    ): void {
        $jwt = $this->getJwt();
        $builtSigner = $jwt->buildSigner($signer);
        $builtSigningKey = $jwt->buildKey($signingKey);
        $token = $jwt->getBuilder()->getToken($builtSigner, $builtSigningKey);
        $tokenParsed = $jwt->parse($token->toString());
        self::assertSame('JWT', $tokenParsed->headers()->get('typ'));
        self::assertSame($algorithm, $tokenParsed->headers()->get('alg'));

        self::assertTrue(
            $jwt->getValidator()->validate(
                $tokenParsed,
                new SignedWith($builtSigner, $verifyingKey ? $jwt->buildKey($verifyingKey) : $builtSigningKey)
            )
        );
    }

    public function testInvalidSignerId(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Invalid signer ID!');
        $this->getJwt()->buildSigner('Invalid');
    }

    public function testEmptyKey(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Empty string used as a key configuration!');
        $this->getJwt()->buildKey('');
    }

    public function testInvalidKeyWithNotEnoughBits(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits, only 56 bits provided');
        $jwt = $this->getJwt();
        $signer = $jwt->buildSigner(Jwt::HS256);
        $token = $jwt->getBuilder()->getToken($signer, $jwt->buildKey('secret1'));
        $jwt->parse($token->toString());
    }
}
