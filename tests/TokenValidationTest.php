<?php declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Token;

class TokenValidationTest extends \PHPUnit\Framework\TestCase
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
     * @throws \yii\base\InvalidConfigException
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
     * @throws \yii\base\InvalidConfigException
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
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateToken(): void
    {
        $this->assertTrue($this->getJwt()->validateToken($this->createToken(), null, [
            'iss' => static::$issuer,
            'aud' => static::$audience,
            'jti' => static::$id,
        ]));
    }

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateDiff(): void
    {
        $this->assertFalse($this->getJwt()->validateToken($this->createToken(), null, [
            'aud' => 'different',
        ]));
    }

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateTokenTimeout(): void
    {
        $this->assertFalse($this->getJwt()->validateToken($this->createToken(), time() + 4000));
    }

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateTokenPremature(): void
    {
        $this->assertFalse($this->getJwt()->validateToken($this->createToken(60)));
    }
}
