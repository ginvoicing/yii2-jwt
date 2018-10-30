<?php

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
    public $jwt;

    public function setUp(): void
    {
        $this->jwt = \Yii::createObject([
            'class' => Jwt::class,
            'key' => 'secret',
        ]);
    }

    public function createToken(): Token
    {
        return $this->jwt->getBuilder()
            ->setIssuer(static::$issuer)
            ->setAudience(static::$audience)
            ->setId(static::$id, true)
            ->setIssuedAt(time())
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->getToken();
    }
    
    public function getValidationData(): ValidationData
    {
        $data = $this->jwt->getValidationData();

        $data->setIssuer(static::$issuer);
        $data->setAudience(static::$audience);
        $data->setId(static::$id);

        return $data;
    }

    public function testValidateToken(): void
    {
        $token = $this->createToken();
        $data = $this->getValidationData();

        $this->assertTrue($token->validate($data));
    }
    
    public function testValidateTokenTimeout(): void
    {
        $token = $this->createToken();
        $data = $this->getValidationData();

        $data->setCurrentTime(time() + 4000);

        $this->assertFalse($token->validate($data));
    }
}
