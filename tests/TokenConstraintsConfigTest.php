<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Closure;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;

class TokenConstraintsConfigTest extends TestCase
{
    /**
     * @param array|Closure|null $validationConstraints
     * @throws InvalidConfigException
     */
    private function getJwt($validationConstraints): Jwt
    {
        return Yii::createObject(
            [
                'class' => Jwt::class,
                'validationConstraints' => $validationConstraints
            ]
        );
    }

    private function getToken(Jwt $jwt): Token
    {
        return $jwt->getBuilder()->identifiedBy('test')->getToken(
            $jwt->getConfiguration()->signer(),
            $jwt->getConfiguration()->signingKey()
        );
    }

    public function testArrayConfigWithObjects(): void
    {
        $jwt = $this->getJwt([new IdentifiedBy('test')]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testArrayConfigWithArray(): void
    {
        $jwt = $this->getJwt([[IdentifiedBy::class, ['test']]]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testArrayConfigWithClosure(): void
    {
        $jwt = $this->getJwt(static function (Jwt $jwt) {
            return [new IdentifiedBy('test')];
        });

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }
}
