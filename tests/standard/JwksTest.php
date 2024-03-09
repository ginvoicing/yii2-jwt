<?php

declare(strict_types=1);

namespace bizley\tests\standard;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;

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
        // yield 'Direct signer provided' => [
        //     [
        //         'signer' => new Sha256(),
        //         'signingKey' => 'secret1secret1secret1secret1secret1secret1',
        //     ],
        //     Jwt::HS256
        // ];
        // yield 'Direct key provided' => [
        //     [
        //         'signer' => Jwt::HS256,
        //         'signingKey' => InMemory::plainText('secret1secret1secret1secret1secret1secret1')
        //     ],
        //     Jwt::HS256
        // ];
        // yield 'HS256' => [
        //     [
        //         'signer' => Jwt::HS256,
        //         'signingKey' => 'secret1secret1secret1secret1secret1secret1',
        //     ],
        //     Jwt::HS256
        // ];
        // yield 'HS256 base64' => [
        //     [
        //         'signer' => Jwt::HS256,
        //         'signingKey' => [
        //             Jwt::KEY => 'c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0MXNlY3JldDFzZWNyZXQx',
        //             Jwt::METHOD => JWT::METHOD_BASE64
        //         ],
        //     ],
        //     Jwt::HS256
        // ];
        // yield 'HS384' => [
        //     [
        //         'signer' => Jwt::HS384,
        //         'signingKey' => 'secret1secret1secret1secret1secret1secret1secret1',
        //     ],
        //     Jwt::HS384
        // ];
        // yield 'HS512' => [
        //     [
        //         'signer' => Jwt::HS512,
        //         'signingKey' => 'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
        //     ],
        //     Jwt::HS512
        // ];
        // yield 'HS256 pass' => [
        //     [
        //         'signer' => Jwt::HS256,
        //         'signingKey' => [
        //             Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
        //             Jwt::PASSPHRASE => 'passphrase'
        //         ],
        //     ],
        //     Jwt::HS256
        // ];
        // yield 'HS384 pass' => [
        //     [
        //         'signer' => Jwt::HS384,
        //         'signingKey' => [
        //             Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1',
        //             Jwt::PASSPHRASE => 'passphrase'
        //         ],
        //     ],
        //     Jwt::HS384
        // ];
        // yield 'HS512 pass' => [
        //     [
        //         'signer' => Jwt::HS512,
        //         'signingKey' => [
        //             Jwt::KEY => 'secret1secret1secret1secret1secret1secret1secret1secret1secret1secret1',
        //             Jwt::PASSPHRASE => 'passphrase'
        //         ],
        //     ],
        //     Jwt::HS512
        // ];
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
     * @dataProvider providerForSigners
     * @throws InvalidConfigException
     */
    public function testJwks(array $config, string $algorithm): void
    {
        $jwt = $this->getJwt($config);
        $kid = md5('secret1secret2');
        $jwks = $jwt->getJwks($kid);
        self::assertSame($algorithm,$jwks['alg']);
        self::assertSame($kid,$jwks['kid']);
        self::assertNotEmpty($jwks['n']);
    }
}
