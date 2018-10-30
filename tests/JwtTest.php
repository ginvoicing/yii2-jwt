<?php

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

class JwtTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Secret key
     */
    public const SECRET = 'secret';
    
    /**
     * Issuer
     */
    public const ISSUER = 'http://example.com';
    
    /**
     * Audience
     */
    public const AUDIENCE = 'http://example.org';
    
    /**
     * Id
     */
    public const ID = '4f1g23a12aa';

    /**
     * @var Jwt
     */
    public $jwt;

    public function setUp(): void
    {
        $this->jwt = \Yii::createObject([
            'class' => Jwt::class,
            'key' => self::SECRET,
        ]);
    }

    public function getSignerSha256(): Sha256
    {
        return new Sha256();
    }

    public function createTokenWithSignature(): Token
    {
        return $this->jwt
            ->getBuilder()->setIssuer(self::ISSUER) // Configures the issuer (iss claim)
            ->setAudience(self::AUDIENCE) // Configures the audience (aud claim)
            ->setId(self::ID, true) // Configures the id (jti claim), replicating as a header item
            ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
            ->setExpiration(time() + 3600) // Configures the expiration time of the token (nbf claim)
            ->set('uid', 1) // Configures a new claim, called "uid"
            ->sign($this->getSignerSha256(), $this->jwt->key) // creates a signature using "testing" as key
            ->getToken(); // Retrieves the generated token
    }
    
    public function getValidationData(): ValidationData
    {
        $data = $this->jwt->getValidationData(); // It will use the current time to validate (iat, nbf and exp)

        $data->setIssuer(self::ISSUER);
        $data->setAudience(self::AUDIENCE);
        $data->setId(self::ID);

        return $data;
    }

    public function testValidateTokenWithSignature(): void
    {
        $token = $this->createTokenWithSignature();
        $data = $this->getValidationData();

        $this->assertTrue($token->verify($this->getSignerSha256(), $this->jwt->key));
        $this->assertTrue($token->validate($data));
    }
    
    public function testValidateTokenTimeoutWithSignature(): void
    {
        $token = $this->createTokenWithSignature();
        $data = $this->getValidationData();

        $data->setCurrentTime(time() + 4000); // changing the validation time to future

        $this->assertFalse($token->validate($data)); // false, because token is expired since current time is greater than exp
    }
}
