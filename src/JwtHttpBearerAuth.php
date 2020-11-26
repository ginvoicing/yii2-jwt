<?php

declare(strict_types=1);

namespace bizley\jwt;

use Closure;
use Lcobucci\JWT\Token;
use Throwable;
use Yii;
use yii\base\InvalidConfigException;
use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;
use yii\web\IdentityInterface;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
use yii\web\User;

use function call_user_func;
use function get_class;

/**
 * JwtHttpBearerAuth is an action filter that supports the authentication method based on HTTP Bearer JSON Web Token.
 *
 * You may use JwtHttpBearerAuth by attaching it as a behavior to a controller or module, like the following:
 *
 * ```php
 * public function behaviors()
 * {
 *     return [
 *         'JWTBearerAuth' => [
 *             'class' => \bizley\jwt\JwtHttpBearerAuth::class,
 *         ],
 *     ];
 * }
 * ```
 *
 * @author Paweł Bizley Brzozowski <pawel@positive.codes> since 2.0 (fork)
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 */
class JwtHttpBearerAuth extends HttpBearerAuth
{
    /**
     * @var string|array|Jwt application component ID of the JWT handler, configuration array, or JWT handler object
     * itself. By default it's assumes that component of ID "jwt" has been configured.
     */
    public $jwt = 'jwt';

    /**
     * @var Closure|null anonymous function that should return identity of user authenticated with the JWT payload
     * information. It should have the following signature:
     *
     * ```php
     * function (Token $token)
     * ```
     *
     * where $token is JSON Web Token provided in the HTTP header.
     * If $auth is not provided method User::loginByAccessToken() will be called instead.
     */
    public ?Closure $auth = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        if (empty($this->pattern)) {
            throw new InvalidConfigException('You must provide pattern to use to extract the HTTP authentication value!');
        }

        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
    }

    /**
     * Authenticates the current user.
     * @param User $user
     * @param Request $request
     * @param Response $response
     * @return IdentityInterface|null the authenticated user identity. If authentication information is not provided, null will be returned.
     * @throws UnauthorizedHttpException if authentication information is provided but is invalid.
     */
    public function authenticate($user, $request, $response): ?IdentityInterface // BC signature
    {
        $authHeader = $request->getHeaders()->get($this->header);

        if ($authHeader === null || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        $identity = null;
        $token = null;

        try {
            $token = $this->processToken($matches[1]);
        } catch (Throwable $exception) {
            Yii::warning($exception->getMessage(), 'JwtHttpBearerAuth');
            $this->fail($response);
        }

        if ($token !== null) {
            if ($this->auth instanceof Closure) {
                $identity = call_user_func($this->auth, $token);
            } else {
                $identity = $user->loginByAccessToken($token->toString(), get_class($this));
            }
        }

        if ($identity === null) {
            $this->fail($response);
        }

        return $identity;
    }

    /**
     * Parses and validates the JWT token.
     * @param string $data data provided in HTTP header, presumably JWT
     * @return Token|null
     */
    public function processToken(string $data): ?Token
    {
        $token = $this->jwt->parse($data);

        return $this->jwt->validate($token) ? $token : null;
    }

    /**
     * @throws UnauthorizedHttpException
     */
    public function fail(Response $response): void
    {
        $this->challenge($response);
        $this->handleFailure($response);
    }

    /**
     * Handles authentication failure.
     * @param Response $response
     * @throws UnauthorizedHttpException
     */
    public function handleFailure($response): void // BC signature
    {
        throw new UnauthorizedHttpException('Your request was made with invalid or expired JSON Web Token.');
    }
}
