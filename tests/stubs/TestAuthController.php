<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use bizley\jwt\JwtHttpBearerAuth;
use Yii;
use yii\rest\Controller;

class TestAuthController extends Controller
{
    public array $filterConfig = [];

    public function behaviors(): array
    {
        return [
            'authenticator' => array_merge(
                ['class' => JwtHttpBearerAuth::class],
                $this->filterConfig
            )
        ];
    }

    public function actionFiltered(): ?string
    {
        return Yii::$app->user->id;
    }
}
