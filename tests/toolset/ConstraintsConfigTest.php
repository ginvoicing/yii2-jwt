<?php

declare(strict_types=1);

namespace bizley\tests\toolset;

use bizley\jwt\Jwt;
use bizley\jwt\JwtTools;
use bizley\tests\stubs\YiiConstraint;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Jwt::class)]
#[CoversClass(JwtTools::class)]
class ConstraintsConfigTest extends TestCase
{
    private function getJwt(array|\Closure|null $validationConstraints): JwtTools
    {
        /** @var JwtTools $jwt */
        $jwt = \Yii::createObject(
            [
                'class' => JwtTools::class,
                'validationConstraints' => $validationConstraints,
            ]
        );

        return $jwt;
    }

    private function getToken(JwtTools $jwt): Token
    {
        return $jwt->getBuilder()->identifiedBy('test')->relatedTo('test')->getToken(
            $jwt->buildSigner(Jwt::HS256),
            $jwt->buildKey('c2VjcmV0MXNlY3JldDFzZWNyZXQxc2VjcmV0M')
        );
    }

    #[Test]
    public function arrayConfigWithObjects(): void
    {
        $jwt = $this->getJwt([new Constraint\IdentifiedBy('test'), new Constraint\RelatedTo('test')]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    #[Test]
    public function arrayConfigWithArray(): void
    {
        $jwt = $this->getJwt([[Constraint\IdentifiedBy::class, ['test']], [Constraint\RelatedTo::class, ['test']]]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    #[Test]
    public function arrayConfigWithYiiArray(): void
    {
        $jwt = $this->getJwt([['class' => YiiConstraint::class, 'test' => 'yii']]);

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    #[Test]
    public function arrayConfigWithClosure(): void
    {
        $jwt = $this->getJwt(static function (JwtTools $jwt) {
            return [new Constraint\IdentifiedBy('test'), new Constraint\RelatedTo('test')];
        });

        self::assertTrue($jwt->validate($this->getToken($jwt)));
    }

    #[Test]
    public function defaultConfig(): void
    {
        $jwt = $this->getJwt(null);

        $this->expectException(NoConstraintsGiven::class);
        $jwt->validate($this->getToken($jwt));
    }

    #[Test]
    public function arrayConfigWithCustomConstraints(): void
    {
        $constraint1 = $this->createMock(Constraint::class);
        $constraint1->expects($this->once())->method('assert');
        $constraint2 = $this->createMock(Constraint::class);
        $constraint2->expects($this->once())->method('assert');

        $jwt = $this->getJwt([$constraint1, $constraint2]);
        $jwt->validate($this->getToken($jwt));
    }

    #[Test]
    public function directConfigWithCustomConstraints(): void
    {
        $constraint1 = $this->createMock(Constraint::class);
        $constraint1->expects($this->once())->method('assert');
        $constraint2 = $this->createMock(Constraint::class);
        $constraint2->expects($this->once())->method('assert');

        $jwt = $this->getJwt(null);
        $jwt->validationConstraints = [$constraint1, $constraint2];
        $jwt->validate($this->getToken($jwt));
    }
}
