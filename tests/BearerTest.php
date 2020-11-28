<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use bizley\jwt\JwtHttpBearerAuth;
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
                    'key' => 'secret',
                ],
            ],
            'controllerMap' => [
                'test-auth' => TestAuthController::class,
            ],
        ]);
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
        $token = Yii::$app->jwt->getBuilder()
            ->setIssuedAt(time() - 100)
            ->setExpiration(time() - 50)
            ->getToken();

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
        $token = Yii::$app->jwt->getBuilder()
                    ->setIssuedAt(time())
                    ->setExpiration(time() + 3600)
                    ->setSubject('test')
                    ->sign(new \Lcobucci\JWT\Signer\Hmac\Sha256(), Yii::$app->jwt->key)
                    ->getToken();

        UserIdentity::$token = (string) $token;

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        /* @var $controller Controller */
        $controller = Yii::$app->createController('test-auth')[0];

        self::assertEquals('test', $controller->run('filtered'));
    }

    /**
     * @throws InvalidConfigException
     */
    public function testHttpBearerAuthCustom(): void
    {
        $token = Yii::$app->jwt->getBuilder()
            ->setIssuedAt(time())
            ->setExpiration(time() + 3600)
            ->setSubject('test')
            ->sign(new \Lcobucci\JWT\Signer\Hmac\Sha256(), Yii::$app->jwt->key)
            ->getToken();

        Yii::$app->request->headers->set('Authorization', "Bearer $token");

        $controller = Yii::$app->createController('test-auth')[0];
        $controller->filterConfig['auth'] = function (\Lcobucci\JWT\Token $token) {
            $identity = UserIdentity::findIdentity($token->getClaim('sub'));
            Yii::$app->user->switchIdentity($identity);
            return $identity;
        };

        /* @var $controller Controller */
        self::assertEquals('test', $controller->run('filtered'));
    }
}

class TestAuthController extends Controller
{
    public $filterConfig = [];

    /**
     * @return array
     */
    public function behaviors(): array
    {
        return ['authenticator' => array_merge(
            ['class' => JwtHttpBearerAuth::class],
            $this->filterConfig
        )];
    }

    /**
     * @return string|null
     */
    public function actionFiltered(): ?string
    {
        return Yii::$app->user->id;
    }
}
