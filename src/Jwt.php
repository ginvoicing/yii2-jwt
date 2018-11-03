<?php declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Yii;

/**
 * JSON Web Token implementation based on lcobucci/jwt library.
 * @see https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 * @author Paweł Bizley Brzozowski <pawel@positive.codes> since 2.0 (fork)
 */
class Jwt extends \yii\base\Component
{
    /**
     * @var array Token signers
     * @since 2.0
     */
    public $signers = [
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
        'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
        'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
    ];

    /**
     * @var string Secret key string or path to the public key file.
     * For path you can use Yii alias (starting with `@` character) or direct file path (starting with `file://`).
     */
    public $key;

    /**
     * Initializes builder.
     * @param Encoder|null $encoder
     * @param Factory|null $claimFactory
     * @return Builder
     */
    public function getBuilder(?Encoder $encoder = null, ?Factory $claimFactory = null): Builder
    {
        return new Builder($encoder, $claimFactory);
    }

    /**
     * Initializes parser.
     * @param Decoder|null $decoder
     * @param Factory|null $claimFactory
     * @return Parser
     */
    public function getParser(?Decoder $decoder = null, ?Factory $claimFactory = null): Parser
    {
        return new Parser($decoder, $claimFactory);
    }

    /**
     * Initializes validation data wrapper.
     * @param int|null $currentTime UNIX timestamp or null for time()
     * @return ValidationData
     */
    public function getValidationData(?int $currentTime = null): ValidationData
    {
        return new ValidationData($currentTime);
    }

    /**
     * Parses data and returns JSON Web Token.
     * @param string $data Raw JWT to be parsed
     * @param bool $validate whether token should be validated
     * @param bool $verify whether token should be verified
     * @return Token|null
     */
    public function loadToken(string $data, bool $validate = true, bool $verify = true): ?Token
    {
        try {
            $token = $this->getParser()->parse($data);

            if ($validate && !$this->validateToken($token)) {
                return null;
            }

            if ($verify && !$this->verifyToken($token)) {
                return null;
            }

            return $token;

        } catch (\Throwable $exception) {
            Yii::warning('Error while parsing JWT: ' . $exception->getMessage(), 'jwt');
            return null;
        }
    }

    /**
     * Validates token.
     * @param Token $token
     * @param int|null $currentTime UNIX timestamp or null for time()
     * @param array $validationItems array of items to validate where key is an item's name and value is a string
     * Available items (array keys) are:
     * - 'jti': ID,
     * - 'iss': issuer,
     * - 'aud': audience,
     * - 'sub': subject.
     * This parameter is available from version 2.0.
     * @return bool
     */
    public function validateToken(Token $token, ?int $currentTime = null, array $validationItems = []): bool
    {
        $data = $this->getValidationData($currentTime);

        if (array_key_exists('jti', $validationItems)) {
            $data->setId($validationItems['jti']);
        }
        if (array_key_exists('iss', $validationItems)) {
            $data->setIssuer($validationItems['iss']);
        }
        if (array_key_exists('aud', $validationItems)) {
            $data->setAudience($validationItems['aud']);
        }
        if (array_key_exists('sub', $validationItems)) {
            $data->setSubject($validationItems['sub']);
        }

        return $token->validate($data);
    }

    /**
     * Verifies token.
     * @param Token $token
     * @return bool
     * @throws \yii\base\NotSupportedException
     * @throws \yii\base\InvalidConfigException
     */
    public function verifyToken(Token $token): bool
    {
        $alg = $token->getHeader('alg');

        if (!array_key_exists($alg, $this->signers)) {
            throw new \yii\base\NotSupportedException("Signer algorithm '{$alg}' not supported!");
        }

        /* @var $signer \Lcobucci\JWT\Signer */
        $signer = Yii::createObject($this->signers[$alg]);

        return $token->verify($signer, $this->prepareKey($this->key));
    }

    /**
     * Detects key file path and resolves Yii alias if given.
     * @param string $key
     * @return string|null
     * @throws \LogicException when file path does not exist or is not readable
     * @since 2.0
     */
    public function prepareKey(string $key): ?string
    {
        $keyPath = null;

        if (strpos($key, '@') === 0) {
            $keyPath = 'file://' . Yii::getAlias($key);
        } elseif (strpos($key, 'file://') === 0) {
            $keyPath = $key;
        }

        if ($keyPath !== null) {
            if (!file_exists($keyPath) || !is_readable($keyPath)) {
                throw new \LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }

            return $keyPath;
        }

        return $key;
    }
}
