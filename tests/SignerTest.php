<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;

class SignerTest extends TestCase
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

    public function providerForSigners(): array
    {
        return [
            'No signer' => [
                [
                    'signer' => null,
                ],
                'none'
            ],
            'HS256' => [
                [
                    'signer' => Jwt::HS256,
                    'signingKey' => 'secret1',
                ],
                Jwt::HS256
            ],
            'HS384' => [
                [
                    'signer' => Jwt::HS384,
                    'signingKey' => 'secret2',
                ],
                Jwt::HS384
            ],
            'HS512' => [
                [
                    'signer' => Jwt::HS512,
                    'signingKey' => 'secret3',
                ],
                Jwt::HS512
            ],
            'HS256 pass' => [
                [
                    'signer' => Jwt::HS256,
                    'signingKey' => [
                        Jwt::KEY => 'secret1',
                        Jwt::PASSPHRASE => 'passphrase'
                    ],
                ],
                Jwt::HS256
            ],
            'HS384 pass' => [
                [
                    'signer' => Jwt::HS384,
                    'signingKey' => [
                        Jwt::KEY => 'secret2',
                        Jwt::PASSPHRASE => 'passphrase'
                    ],
                ],
                Jwt::HS384
            ],
            'HS512 pass' => [
                [
                    'signer' => Jwt::HS512,
                    'signingKey' => [
                        Jwt::KEY => 'secret3',
                        Jwt::PASSPHRASE => 'passphrase'
                    ],
                ],
                Jwt::HS512
            ],
            'RS256' => [
                [
                    'signer' => Jwt::RS256,
                    'signingKey' => '@bizley/tests/data/rs256.key',
                    'verifyingKey' => '@bizley/tests/data/rs256.key.pub',
                ],
                Jwt::RS256
            ],
            'RS384' => [
                [
                    'signer' => Jwt::RS384,
                    'signingKey' => '@bizley/tests/data/rs384.key',
                    'verifyingKey' => '@bizley/tests/data/rs384.key.pub',
                ],
                Jwt::RS384
            ],
            'RS512' => [
                [
                    'signer' => Jwt::RS512,
                    'signingKey' => '@bizley/tests/data/rs512.key',
                    'verifyingKey' => '@bizley/tests/data/rs512.key.pub',
                ],
                Jwt::RS512
            ],
            'ES256' => [
                [
                    'signer' => Jwt::ES256,
                    'signingKey' => '@bizley/tests/data/es256.key',
                    'verifyingKey' => '@bizley/tests/data/es256.key.pub',
                ],
                Jwt::ES256
            ],
            'ES384' => [
                [
                    'signer' => Jwt::ES384,
                    'signingKey' => '@bizley/tests/data/es384.key',
                    'verifyingKey' => '@bizley/tests/data/es384.key.pub',
                ],
                Jwt::ES384
            ],
            'ES512' => [
                [
                    'signer' => Jwt::ES512,
                    'signingKey' => '@bizley/tests/data/es512.key',
                    'verifyingKey' => '@bizley/tests/data/es512.key.pub',
                ],
                Jwt::ES512
            ],

        ];
    }

    /**
     * @dataProvider providerForSigners
     * @throws InvalidConfigException
     */
    public function testParseTokenWithSignature(array $config, string $algorithm): void
    {
        $jwt = $this->getJwt($config);
        $signer = $jwt->getConfiguration()->signer();
        $token = $jwt->getBuilder()->getToken($signer, $jwt->getConfiguration()->signingKey());
        $tokenParsed = $jwt->parse($token->toString());
        self::assertSame('JWT', $tokenParsed->headers()->get('typ'));
        self::assertSame($algorithm, $tokenParsed->headers()->get('alg'));

        self::assertTrue($jwt->getConfiguration()->validator()->validate(
            $tokenParsed,
            new SignedWith($signer, $jwt->getConfiguration()->verificationKey()))
        );
    }
}
