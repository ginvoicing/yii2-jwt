<?php

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Token;

abstract class SignerTestCase extends \PHPUnit\Framework\TestCase
{
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

    abstract public function getSigner();

    public function createTokenWithSignature(): Token
    {
        return $this->jwt->getBuilder()->sign($this->getSigner(), $this->jwt->key)->getToken();
    }
    
    public function testValidateTokenWithSignature(): void
    {
        $this->assertTrue($this->createTokenWithSignature()->verify($this->getSigner(), $this->jwt->key));
    }
}
