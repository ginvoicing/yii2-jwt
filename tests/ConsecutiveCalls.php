<?php

declare(strict_types=1);

namespace bizley\tests;

use PHPUnit\Framework\Constraint\Constraint;

class ConsecutiveCalls extends Constraint
{
    /**
     * @var array<mixed>
     */
    private array $stack;
    private int $call = 0;

    public function __construct(mixed ...$args)
    {
        $this->stack = $args;
    }

    protected function matches(mixed $other): bool
    {
        $this->call++;
        $value = array_shift($this->stack);
        if ($value instanceof Constraint) {
            return $value->evaluate($other, '', true); // @phpstan-ignore-line
        }

        return $value === $other;
    }

    public function toString(): string
    {
        return sprintf('was called the #%d time', $this->call);
    }
}
