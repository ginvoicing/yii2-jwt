<?php declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT\Token;
use yii\base\InvalidConfigException;
use yii\web\IdentityInterface;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;

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
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 * @author Paweł Bizley Brzozowski <pawel@positive.codes> since 2.0 (fork)
 */
class JwtHttpBearerAuth extends \yii\filters\auth\HttpBearerAuth
{
    /**
     * @var string|array|Jwt application component ID of the JWT handler, configuration array, or JWT handler object itself.
     * By default it's assumes that component of ID "jwt" has been configured.
     */
    public $jwt = 'jwt';

    /**
     * @var \Closure anonymous function that should return identity of user authenticated with the JWT payload information.
     * It should have the following signature:
     *
     * ```php
     * function (Token $token)
     * ```
     *
     * where $token is JSON Web Token provided in the HTTP header.
     * If $auth is not provided method User::loginByAccessToken() will be called instead.
     */
    public $auth;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->jwt = \yii\di\Instance::ensure($this->jwt, Jwt::class);

        if (empty($this->pattern)) {
            throw new InvalidConfigException('You must provide pattern to use to extract the HTTP authentication value!');
        }
    }

    /**
     * Authenticates the current user.
     * @param \yii\web\User $user
     * @param \yii\web\Request $request
     * @param Response $response
     * @return IdentityInterface the authenticated user identity. If authentication information is not provided, null will be returned.
     * @throws UnauthorizedHttpException if authentication information is provided but is invalid.
     */
    public function authenticate($user, $request, $response): ?IdentityInterface // BC signature
    {
        $authHeader = $request->getHeaders()->get($this->header);

        if ($authHeader === null || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        $identity = null;

        $token = $this->loadToken($matches[1]);
        if ($token !== null) {
            if ($this->auth instanceof \Closure) {
                $identity = \call_user_func($this->auth, $token);
            } else {
                $identity = $user->loginByAccessToken((string) $token, \get_class($this));
            }
        }

        if ($identity === null) {
            $this->challenge($response);
            $this->handleFailure($response);
        }

        return $identity;
    }

    /**
     * Loads the JWT.
     * @param string $data data provided in HTTP header, presumably JWT
     * @return Token|null
     */
    public function loadToken(string $data): ?Token
    {
        return $this->jwt->loadToken($data);
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
