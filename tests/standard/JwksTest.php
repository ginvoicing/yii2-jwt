<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use PHPUnit\Framework\Attributes;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;

#[Attributes\CoversClass(Jwt::class)]
class JwksTest extends TestCase
{
    /**
     * @throws InvalidConfigException
     */
    public function getJwt(array $config = []): Jwt
    {
        /** @var Jwt $jwt */
        $jwt = Yii::createObject(
            array_merge(
                ['class' => Jwt::class],
                $config
            )
        );

        return $jwt;
    }

    public static function providerForSigners(): iterable
    {
        yield 'RS256' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => '@bizley/tests/data/rs256.key',
                'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
        yield 'RS256 with file handler' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => 'file://' . __DIR__ . '/../data/rs256.key',
                'verifyingKey' => 'file://' . __DIR__ . '/../data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
        yield 'RS256 with in-memory file' => [
            [
                'signer' => Jwt::RS256,
                'signingKey' => [
                    Jwt::KEY => 'file://' . __DIR__ . '/../data/rs256.key',
                    Jwt::METHOD => Jwt::METHOD_FILE,
                ],
                'verifyingKey' => 'file://' . __DIR__ . '/../data/rs256.key.pub',
            ],
            Jwt::RS256
        ];
    }

    /**
     * @throws InvalidConfigException
     */
    #[Attributes\DataProvider('providerForSigners')]
    #[Attributes\Test]
    public function jwks(array $config, string $algorithm): void
    {
        $jwt = $this->getJwt($config);
        $kid = md5('secret1secret2');
        $jwks = $jwt->getJwks($kid);
        self::assertSame('RSA', $jwks['kty']);
        self::assertSame($algorithm, $jwks['alg']);
        self::assertSame('sig', $jwks['use']);
        self::assertSame($kid, $jwks['kid']);
        self::assertNotEmpty($jwks['n']);
        self::assertSame('AQAB', $jwks['e']);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Attributes\Test]
    public function jwksForUnsupportedSigner(): void
    {
        $jwt = $this->getJwt([
            'signer' => Jwt::ES256,
            'signingKey' => '@bizley/tests/data/es256.key',
            'verifyingKey' => '@bizley/tests/data/es256.key.pub',
        ]);

        self::assertSame([], $jwt->getJwks('kid'));
    }

    /**
     * @throws InvalidConfigException
     */
    #[Attributes\Test]
    public function jwksForUnreadableKey(): void
    {
        $jwt = $this->getJwt([
            'signer' => Jwt::RS256,
            'signingKey' => 'not-a-key',
            'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
        ]);

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Unable to read the signing key!');
        $jwt->getJwks('kid');
    }

    /**
     * @throws InvalidConfigException
     */
    #[Attributes\Test]
    public function jwksForNonRsaKey(): void
    {
        $jwt = $this->getJwt([
            'signer' => Jwt::RS256,
            'signingKey' => '@bizley/tests/data/es256.key',
            'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
        ]);

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Signing key is not a valid RSA key!');
        $jwt->getJwks('kid');
    }
}
