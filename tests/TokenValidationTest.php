<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

class TokenValidationTest extends TestCase
{
    public static $issuer = 'http://example.com';
    public static $audience = 'http://example.org';
    public static $id = '4f1g23a12aa';

    /**
     * @var Jwt
     */
    protected $jwt;

    /**
     * @param bool $reinit
     * @param array $config
     * @return Jwt
     * @throws InvalidConfigException
     */
    public function getJwt(bool $reinit = false, array $config = []): Jwt
    {
        if ($reinit || $this->jwt === null) {
            $this->jwt = \Yii::createObject(array_merge([
                'class' => Jwt::class,
                'key' => 'secret',
            ], $config));
        }

        return $this->jwt;
    }

    /**
     * @param int $issuedOffset
     * @return Token
     * @throws InvalidConfigException
     */
    public function createToken(int $issuedOffset = 0): Token
    {
        return $this->getJwt()->getBuilder()
            ->setIssuer(static::$issuer)
            ->setAudience(static::$audience)
            ->setId(static::$id, true)
            ->setIssuedAt(time() + $issuedOffset)
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->getToken();
    }

    /**
     * @throws InvalidConfigException
     */
    public function testValidateToken(): void
    {
        self::assertTrue($this->getJwt()->validateToken($this->createToken(), null, [
            'iss' => static::$issuer,
            'aud' => static::$audience,
            'jti' => static::$id,
        ]));
    }

    /**
     * @throws InvalidConfigException
     */
    public function testValidateDiff(): void
    {
        self::assertFalse($this->getJwt()->validateToken($this->createToken(), null, [
            'aud' => 'different',
        ]));
    }

    /**
     * @throws InvalidConfigException
     */
    public function testValidateTokenTimeout(): void
    {
        self::assertFalse($this->getJwt()->validateToken($this->createToken(), time() + 4000));
    }

    /**
     * @throws InvalidConfigException
     */
    public function testValidateTokenPremature(): void
    {
        self::assertFalse($this->getJwt()->validateToken($this->createToken(60)));
    }
}
