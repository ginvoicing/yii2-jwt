<?php

declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation;
use Lcobucci\JWT\Validator;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v5.
 * @see https://github.com/lcobucci/jwt
 *
 * This implementation allows developer to pick & choose JWT tools to use for example in order to only validate
 * a token (without issuing it first, so signing key does not need to be defined).
 *
 * @author Paweł Bizley Brzozowski <pawel@positive.codes>
 * @since 4.1.0
 */
class JwtTools extends Component
{
    /**
     * @var array<string, string[]> Default signers configuration. When instantiated it will use selected array to
     * spread into `Yii::createObject($type, array $params = [])` method so the first array element is $type, and
     * the second is $params.
     */
    public array $signers = [
        Jwt::HS256 => [Signer\Hmac\Sha256::class],
        Jwt::HS384 => [Signer\Hmac\Sha384::class],
        Jwt::HS512 => [Signer\Hmac\Sha512::class],
        Jwt::RS256 => [Signer\Rsa\Sha256::class],
        Jwt::RS384 => [Signer\Rsa\Sha384::class],
        Jwt::RS512 => [Signer\Rsa\Sha512::class],
        Jwt::ES256 => [Signer\Ecdsa\Sha256::class],
        Jwt::ES384 => [Signer\Ecdsa\Sha384::class],
        Jwt::ES512 => [Signer\Ecdsa\Sha512::class],
        Jwt::EDDSA => [Signer\Eddsa::class],
        Jwt::BLAKE2B => [Signer\Blake2b::class],
    ];

    /**
     * @var string|array<string, mixed>|Encoder|null Custom encoder.
     * It can be component's ID, configuration array, or instance of Encoder.
     * In case it's not an instance, it must be resolvable to an Encoder's instance.
     */
    public $encoder;

    /**
     * @var string|array<string, mixed>|Decoder|null Custom decoder.
     * It can be component's ID, configuration array, or instance of Decoder.
     * In case it's not an instance, it must be resolvable to a Decoder's instance.
     */
    public $decoder;

    /**
     * @var array<array<mixed>|(callable(): mixed)|string>|(callable(): mixed)|null List of constraints that
     * will be used to validate against or an anonymous function that can be resolved as such list. The signature of
     * the function should be `function(\bizley\jwt\JwtTools|\bizley\jwt\Jwt $jwt)` where $jwt will be an instance of
     * this component.
     * For the constraints you can use instances of Lcobucci\JWT\Validation\Constraint or configuration arrays to be
     * resolved as such.
     */
    public $validationConstraints;

    /**
     * @param array<array<mixed>|(callable(): mixed)|string> $config
     * @return object
     * @throws InvalidConfigException
     */
    private function buildObjectFromArray(array $config): object
    {
        $keys = \array_keys($config);
        if (\is_string(\reset($keys))) {
            // most probably Yii-style config
            return Yii::createObject($config);
        }

        return Yii::createObject(...$config);
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for details of using the builder.
     * @throws InvalidConfigException
     */
    public function getBuilder(?ClaimsFormatter $claimFormatter = null): Builder
    {
        return new Token\Builder($this->prepareEncoder(), $claimFormatter ?? ChainedFormatter::default());
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for details of using the parser.
     * @throws InvalidConfigException
     */
    public function getParser(): Parser
    {
        return new Token\Parser($this->prepareDecoder());
    }

    /**
     * @see https://lcobucci-jwt.readthedocs.io/en/stable/validating-tokens/ for details of using the validator.
     */
    public function getValidator(): Validator
    {
        return new Validation\Validator();
    }

    /**
     * @param non-empty-string $jwt
     * @throws CannotDecodeContent When something goes wrong while decoding.
     * @throws Token\InvalidTokenStructure When token string structure is invalid.
     * @throws Token\UnsupportedHeaderFound When parsed token has an unsupported header.
     * @throws InvalidConfigException
     */
    public function parse(string $jwt): Token
    {
        return $this->getParser()->parse($jwt);
    }

    /**
     * This method goes through every single constraint in the set, groups all the violations, and throws an exception
     * with the grouped violations.
     * @param non-empty-string|Token $jwt JWT string or instance of Token
     * @throws Validation\RequiredConstraintsViolated When constraint is violated
     * @throws Validation\NoConstraintsGiven When no constraints are provided
     * @throws InvalidConfigException
     */
    public function assert($jwt): void
    {
        $token = $jwt instanceof Token ? $jwt : $this->parse($jwt);
        $constraints = $this->prepareValidationConstraints();
        $this->getValidator()->assert($token, ...$constraints);
    }

    /**
     * This method return false on first constraint violation
     * @param non-empty-string|Token $jwt JWT string or instance of Token
     * @throws InvalidConfigException
     */
    public function validate($jwt): bool
    {
        $token = $jwt instanceof Token ? $jwt : $this->parse($jwt);
        $constraints = $this->prepareValidationConstraints();

        return $this->getValidator()->validate($token, ...$constraints);
    }

    /**
     * Returns the key based on the definition.
     * @param string|array<string, string>|Signer\Key $key
     * @return Signer\Key
     * @throws InvalidConfigException
     */
    public function buildKey($key): Signer\Key
    {
        if ($key instanceof Signer\Key) {
            return $key;
        }

        if (\is_string($key)) {
            if ($key === '') {
                throw new InvalidConfigException('Empty string used as a key configuration!');
            }
            if (\str_starts_with($key, '@')) {
                $keyConfig = [
                    Jwt::KEY => Yii::getAlias($key),
                    Jwt::METHOD => Jwt::METHOD_FILE,
                ];
            } elseif (\str_starts_with($key, 'file://')) {
                $keyConfig = [
                    Jwt::KEY => $key,
                    Jwt::METHOD => Jwt::METHOD_FILE,
                ];
            } else {
                $keyConfig = [
                    Jwt::KEY => $key,
                    Jwt::METHOD => Jwt::METHOD_PLAIN,
                ];
            }
        } elseif (\is_array($key)) {
            $keyConfig = $key;
        } else {
            throw new InvalidConfigException('Invalid key configuration!');
        }

        $value = $keyConfig[Jwt::KEY] ?? '';
        $method = $keyConfig[Jwt::METHOD] ?? Jwt::METHOD_PLAIN;
        $passphrase = $keyConfig[Jwt::PASSPHRASE] ?? '';

        if (!\is_string($value) || $value === '') {
            throw new InvalidConfigException('Invalid key value!');
        }
        if (!\in_array($method, [Jwt::METHOD_PLAIN, Jwt::METHOD_BASE64, Jwt::METHOD_FILE], true)) {
            throw new InvalidConfigException('Invalid key method!');
        }
        if (!\is_string($passphrase)) {
            throw new InvalidConfigException('Invalid key passphrase!');
        }

        if ($method === Jwt::METHOD_BASE64) {
            return Signer\Key\InMemory::base64Encoded($value, $passphrase);
        }
        if ($method === Jwt::METHOD_FILE) {
            return Signer\Key\InMemory::file($value, $passphrase);
        }

        return Signer\Key\InMemory::plainText($value, $passphrase);
    }

    /**
     * @param string|Signer $signer
     * @return Signer
     * @throws InvalidConfigException
     */
    public function buildSigner($signer): Signer
    {
        if ($signer instanceof Signer) {
            return $signer;
        }

        if (!\array_key_exists($signer, $this->signers)) {
            throw new InvalidConfigException('Invalid signer ID!');
        }

        if (\in_array($signer, [Jwt::ES256, Jwt::ES384, Jwt::ES512], true)) {
            Yii::$container->set(Signer\Ecdsa\SignatureConverter::class, Signer\Ecdsa\MultibyteStringConverter::class);
        }

        /** @var Signer $signerInstance */
        $signerInstance = $this->buildObjectFromArray($this->signers[$signer]);

        return $signerInstance;
    }

    /**
     * @return Validation\Constraint[]
     * @throws InvalidConfigException
     */
    protected function prepareValidationConstraints(): array
    {
        if (\is_array($this->validationConstraints)) {
            $constraints = [];

            foreach ($this->validationConstraints as $constraint) {
                if ($constraint instanceof Validation\Constraint) {
                    $constraints[] = $constraint;
                } else {
                    /** @var Validation\Constraint $constraintInstance */
                    $constraintInstance = $this->buildObjectFromArray($constraint);
                    $constraints[] = $constraintInstance;
                }
            }

            return $constraints;
        }

        if (\is_callable($this->validationConstraints)) {
            /** @phpstan-ignore-next-line */
            return \call_user_func($this->validationConstraints, $this);
        }

        return [];
    }

    private ?Encoder $builtEncoder = null;

    /**
     * @throws InvalidConfigException
     */
    protected function prepareEncoder(): Encoder
    {
        if ($this->builtEncoder === null) {
            if ($this->encoder === null) {
                $this->builtEncoder = new JoseEncoder();
            } else {
                /** @var Encoder $encoder */
                $encoder = Instance::ensure($this->encoder, Encoder::class);
                $this->builtEncoder = $encoder;
            }
        }

        return $this->builtEncoder;
    }

    private ?Decoder $builtDecoder = null;

    /**
     * @throws InvalidConfigException
     */
    protected function prepareDecoder(): Decoder
    {
        if ($this->builtDecoder === null) {
            if ($this->decoder === null) {
                $this->builtDecoder = new JoseEncoder();
            } else {
                /** @var Decoder $decoder */
                $decoder = Instance::ensure($this->decoder, Decoder::class);
                $this->builtDecoder = $decoder;
            }
        }

        return $this->builtDecoder;
    }
}
