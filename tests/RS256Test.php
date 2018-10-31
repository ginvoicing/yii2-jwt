<?php declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;

class RS256Test extends SignerTestCase
{
    public $jwtConfig = ['key' => '@bizley/tests/data/rsa256.pub'];

    private $privateKey = '@bizley/tests/data/rsa256';

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return new Sha256();
    }

    /**
     * @param Builder $builder
     * @return Builder
     * @throws \yii\base\InvalidConfigException
     */
    public function sign(Builder $builder): Builder
    {
        return $builder->sign($this->getSigner(), $this->getJwt()->prepareKey($this->privateKey));
    }

    /**
     * @param Token $token
     * @return bool
     * @throws \yii\base\InvalidConfigException
     */
    public function verify(Token $token): bool
    {
        return $token->verify($this->getSigner(), $this->getJwt()->prepareKey($this->getJwt()->key));
    }
}
