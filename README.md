# JWT Integration For Yii 2

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for 
[Yii 2 framework](https://www.yiiframework.com).

> This is fork of [sizeg/yii2-jwt](https://github.com/sizeg/yii2-jwt) package

## Installation

Add the package to your `composer.json`:

    {
        "require": {
            "bizley/jwt": "^2.0"
        }
    }

and run `composer update` or alternatively run `composer require bizley/jwt:^2.0`

## Basic usage

Add `jwt` component to your configuration file:

    [
        'components' => [
            'jwt' => [
                'class' => \bizley\jwt\Jwt::class,
            ],
        ],
    ],


### REST authentication

Configure the `authenticator` behavior in controller.

    class ExampleController extends Controller
    {
        public function behaviors()
        {
            $behaviors = parent::behaviors();
            
            $behaviors['authenticator'] = [
                'class' => \bizley\jwt\JwtHttpBearerAuth::class,
            ];
    
            return $behaviors;
        }
    }


For other configuration options refer to the [Yii 2 Guide](https://www.yiiframework.com/doc/guide/2.0/en/rest-authentication).

### JWT Basic Usage

Please refer to the [lcobucci/jwt Documentation](https://github.com/lcobucci/jwt/blob/3.2/README.md).

## JSON Web Tokens

- https://jwt.io