<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use bizley\jwt\JwtHttpBearerAuth;
use yii\rest\Controller;

class TestStubController extends Controller
{
    public function behaviors(): array
    {
        return [
            'authenticator' => [
                'class' => JwtHttpBearerAuth::class,
                'pattern' => null,
            ],
        ];
    }

    public function actionTest(): ?string
    {
        return null;
    }
}
