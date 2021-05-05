<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use yii\base\BaseObject;

class YiiConstraint extends BaseObject implements Constraint
{
    public string $test;

    public function assert(Token $token): void
    {
    }
}
