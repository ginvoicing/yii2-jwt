<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use PHPUnit\Framework\TestCase;
use Yii;
use yii\base\InvalidConfigException;
use yii\rest\Controller;
use yii\web\Application;
use yii\web\UnauthorizedHttpException;

class BearerTest extends TestCase
{
    /**
     * @throws InvalidConfigException
     */
    protected function setUp(): void
    {
        new Application([
            'id' => 'test',
            'basePath' => __DIR__,
            'vendorPath' => __DIR__ . '/../vendor',
            'components' => [
                'user' => [
                    'identityClass' => UserIdentity::class,
                    'enableSession' => false,
                ],
                'request' => [
                    'enableCookieValidation' => false,
                    'scriptFile' => __DIR__ . '/index.php',
                    'scriptUrl' => '/index.php',
                ],
                'jwt' => [
                    'class' => Jwt::class,
                    'signer' => Jwt::HS256,
                    'signingKey' => 'secret',
                ],
            ],
            'controllerMap' => [
                'test-auth' => TestAuthController::class,
            ],
        ]);
    }

    protected function getJwt(): Jwt
    {
        return Yii::$app->jwt;
    }

    /**
     * @throws InvalidConfigException
     */
    public function testHttpBearerAuthInvalidToken(): void
    {
        Yii::$app->request->headers->set('Authorization', 'Bearer InvalidToken');

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];

        try {
            $controller->run('filtered');
            self::fail('Should throw UnauthorizedHttpException');
        } catch (UnauthorizedHttpException $e) {
            self::assertArrayHasKey('WWW-Authenticate', Yii::$app->getResponse()->getHeaders());
        }
    }

    /**
     * @throws InvalidConfigException
     */
    public function testHttpBearerAuthExpiredToken(): void
    {
        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(new ValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now->modify('-10 minutes'))
            ->expiresAt($now->modify('-5 minutes'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];

        try {
            $controller->run('filtered');
            self::fail('Should throw UnauthorizedHttpException');
        } catch (UnauthorizedHttpException $e) {
            self::assertArrayHasKey('WWW-Authenticate', Yii::$app->getResponse()->getHeaders());
        }
    }

    /**
     * @throws InvalidConfigException
     */
    public function testHttpBearerAuth(): void
    {
        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(new ValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey())
            ->toString();

        UserIdentity::$token = $token;

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /** @var Controller $controller */
        $controller = Yii::$app->createController('test-auth')[0];

        self::assertEquals('test', $controller->run('filtered'));
    }

    /**
     * @throws InvalidConfigException
     */
    public function testHttpBearerAuthCustom(): void
    {
        $now = new DateTimeImmutable();

        $this->getJwt()->getConfiguration()->setValidationConstraints(new ValidAt(SystemClock::fromSystemTimezone()));

        $token = $this->getJwt()->getBuilder()
            ->relatedTo('test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($this->getJwt()->getConfiguration()->signer(), $this->getJwt()->getConfiguration()->signingKey());

        $JWT = $token->toString();

        Yii::$app->request->headers->set('Authorization', "Bearer $JWT");

        /** @var TestAuthController $controller */
        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = static function (Token $token) {
            $identity = UserIdentity::findIdentity($token->claims()->get('sub'));
            Yii::$app->user->switchIdentity($identity);
            return $identity;
        };

        self::assertEquals('test', $controller->run('filtered'));
    }
}
