<?php declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use bizley\jwt\JwtHttpBearerAuth;
use Yii;
use yii\web\UnauthorizedHttpException;

class BearerTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @throws \yii\base\InvalidConfigException
     */
    protected function setUp(): void
    {
        new \yii\web\Application([
            'id' => 'test',
            'basePath' => __DIR__,
            'vendorPath' => __DIR__ . '/../vendor',
            'components' => [
                'user' => [
                    'identityClass' => UserIdentity::class,
                ],
                'request' => [
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

    public function testHttpBearerAuthWrongToken()
    {
        Yii::$app->request->headers->set('Authorization', 'Bearer wrong_token');

        $controller = Yii::$app->createController('test-auth')[0];

        try {
            $controller->run('filtered');
            $this->fail('Should throw UnauthorizedHttpException');
        } catch (UnauthorizedHttpException $e) {
            $this->assertArrayHasKey('WWW-Authenticate', Yii::$app->getResponse()->getHeaders());
        }
    }

//    public function testHttpBearerAuth()
//    {
//        $token = Yii::$app->jwt->getBuilder()->getToken();
//
//        Yii::$app->request->headers->set('Authorization', "Bearer $token");
//
//        $controller = Yii::$app->createController('test-auth')[0];
//
//        try {
//            $controller->run('filtered');
//            $this->fail('Should throw UnauthorizedHttpException');
//        } catch (UnauthorizedHttpException $e) {
//            $this->assertArrayHasKey('WWW-Authenticate', Yii::$app->getResponse()->getHeaders());
//        }
//    }
}

class TestAuthController extends \yii\rest\Controller
{
    /**
     * @return array
     */
    public function behaviors(): array
    {
        return ['authenticator' => JwtHttpBearerAuth::class];
    }

    /**
     * @return string
     */
    public function actionFiltered(): string
    {
        return Yii::$app->user->id;
    }
}
