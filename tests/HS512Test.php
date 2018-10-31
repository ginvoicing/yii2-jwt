<?php declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Token;

class HS512Test extends SignerTestCase
{
    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return new Sha512();
    }

    /**
     * @param Builder $builder
     * @return Builder
     * @throws \yii\base\InvalidConfigException
     */
    public function sign(Builder $builder): Builder
    {
        return $builder->sign($this->getSigner(), $this->getJwt()->key);
    }

    /**
     * @param Token $token
     * @return bool
     * @throws \yii\base\InvalidConfigException
     */
    public function verify(Token $token): bool
    {
        return $token->verify($this->getSigner(), $this->getJwt()->key);
    }
}
