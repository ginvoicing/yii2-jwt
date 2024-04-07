<?php

declare(strict_types=1);

namespace bizley\tests;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Constraint\Constraint;

class ConsecutiveCalls extends Assert
{
    /**
     * @var array<mixed[]>
     */
    private array $data = [];
    private int $internalCounter = -1;

    /**
     * @param mixed[] ...$args
     */
    private function __construct(array ...$args)
    {
        foreach ($args as $arg) {
            if (!\is_array($arg)) {
                throw new \InvalidArgumentException('All arguments must be arrays');
            }

            $this->data[] = $arg;
        }
    }

    /**
     * @param mixed[] ...$arguments
     */
    public static function withArgs(array ...$arguments): self
    {
        return new self(...$arguments);
    }

    public function __invoke(mixed ...$args): void
    {
        $testData = $this->data[++$this->internalCounter] ?? null;
        if ($testData === null) {
            $testData = $this->data[$this->internalCounter % \count($this->data)];
        }

        foreach ($testData as $key => $value) {
            if ($value instanceof Constraint) {
                $value->evaluate($args[$key]);
            } else {
                self::assertEquals($value, $args[$key]);
            }
        }
    }
}
