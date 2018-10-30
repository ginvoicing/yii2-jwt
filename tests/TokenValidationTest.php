<?php declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

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
     * @return Token
     * @throws \yii\base\InvalidConfigException
     */
    public function createToken(): Token
    {
        return $this->getJwt()->getBuilder()
            ->setIssuer(static::$issuer)
            ->setAudience(static::$audience)
            ->setId(static::$id, true)
            ->setIssuedAt(time())
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->getToken();
    }

    /**
     * @return ValidationData
     * @throws \yii\base\InvalidConfigException
     */
    public function getValidationData(): ValidationData
    {
        $data = $this->getJwt()->getValidationData();

        $data->setIssuer(static::$issuer);
        $data->setAudience(static::$audience);
        $data->setId(static::$id);

        return $data;
    }

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateToken(): void
    {
        $token = $this->createToken();
        $data = $this->getValidationData();

        $this->assertTrue($token->validate($data));
    }

    /**
     * @throws \yii\base\InvalidConfigException
     */
    public function testValidateTokenTimeout(): void
    {
        $token = $this->createToken();
        $data = $this->getValidationData();

        $data->setCurrentTime(time() + 4000);

        $this->assertFalse($token->validate($data));
    }
}
