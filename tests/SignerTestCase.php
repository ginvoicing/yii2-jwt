<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

abstract class SignerTestCase extends TestCase
{
    public $jwtConfig = [];

    /**
     * @var Jwt
     */
    protected $jwt;

    /**
     * @return Jwt
     * @throws InvalidConfigException
     */
    public function getJwt(): Jwt
    {
        if ($this->jwt === null) {
            $this->jwt = \Yii::createObject(array_merge([
                'class' => Jwt::class,
                'key' => 'secret',
            ], $this->jwtConfig));
        }

        return $this->jwt;
    }

    abstract public function getSigner(): Signer;

    abstract public function sign(Builder $builder): Builder;

    abstract public function verify(Token $token): bool;

    /**
     * @return Token
     * @throws InvalidConfigException
     */
    public function createTokenWithSignature(): Token
    {
        return $this->sign($this->getJwt()->getBuilder())->getToken();
    }

    /**
     * @throws InvalidConfigException
     */
    public function testValidateTokenWithSignature(): void
    {
        self::assertTrue($this->verify($this->createTokenWithSignature()));
    }
}
