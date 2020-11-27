<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use yii\rest\Controller;

class TestStub2Controller extends Controller
{
    public function behaviors(): array
    {
        return [
            'authenticator' => TestJwtHttpBearerAuth::class,
        ];
    }

    public function actionTest(): ?string
    {
        return null;
    }
}
