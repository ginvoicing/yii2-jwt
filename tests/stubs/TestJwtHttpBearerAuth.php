<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use bizley\jwt\JwtHttpBearerAuth;

class TestJwtHttpBearerAuth extends JwtHttpBearerAuth
{
    public function handleFailure($response): void // BC signature
    {
    }
}
