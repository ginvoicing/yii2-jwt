<?php

declare(strict_types=1);

namespace bizley\tests\stubs;

use bizley\jwt\JwtHttpBearerAuth;

class TestJwtHttpBearerAuth extends JwtHttpBearerAuth
{
    public int $flag = 0;

    public function handleFailure($response): void // BC signature
    {
        $this->flag *= 2;
    }

    public function challenge($response): void
    {
        $this->flag++;
    }
}
