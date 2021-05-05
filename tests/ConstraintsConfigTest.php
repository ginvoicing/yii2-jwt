<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use bizley\tests\stubs\YiiConstraint;
use Closure;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;

class ConstraintsConfigTest extends TestCase
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
        return $jwt->getBuilder()->identifiedBy('test')->relatedTo('test')->getToken(
            $jwt->getConfiguration()->signer(),
            $jwt->getConfiguration()->signingKey()
        );
    }

    public function testArrayConfigWithObjects(): void
    {
        $jwt = $this->getJwt([new IdentifiedBy('test'), new RelatedTo('test')]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testArrayConfigWithArray(): void
    {
        $jwt = $this->getJwt([[IdentifiedBy::class, ['test']], [RelatedTo::class, ['test']]]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testArrayConfigWithYiiArray(): void
    {
        $jwt = $this->getJwt([['class' => YiiConstraint::class, 'test' => 'yii']]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testArrayConfigWithClosure(): void
    {
        $jwt = $this->getJwt(static function (Jwt $jwt) {
            return [new IdentifiedBy('test'), new RelatedTo('test')];
        });

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    public function testDefaultConfig(): void
    {
        $jwt = $this->getJwt(null);

        $this->expectException(NoConstraintsGiven::class);
        $jwt->validate($this->getToken($jwt));
    }

    public function testArrayConfigWithCustomConstraints(): void
    {
        $constraint1 = $this->createMock(Constraint::class);
        $constraint1->expects(self::once())->method('assert');
        $constraint2 = $this->createMock(Constraint::class);
        $constraint2->expects(self::once())->method('assert');

        $jwt = $this->getJwt([$constraint1, $constraint2]);
        $jwt->validate($this->getToken($jwt));
    }

    public function testDirectConfigWithCustomConstraints(): void
    {
        $constraint1 = $this->createMock(Constraint::class);
        $constraint1->expects(self::once())->method('assert');
        $constraint2 = $this->createMock(Constraint::class);
        $constraint2->expects(self::once())->method('assert');

        $jwt = $this->getJwt(null);
        $jwt->getConfiguration()->setValidationConstraints($constraint1, $constraint2);
        $jwt->validate($this->getToken($jwt));
    }
}
