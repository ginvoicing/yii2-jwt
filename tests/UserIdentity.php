<?php declare(strict_types=1);

namespace bizley\tests;

use yii\base\Component;
use yii\base\NotSupportedException;
use yii\web\IdentityInterface;

class UserIdentity extends Component implements IdentityInterface
{
    public static $token;

    /**
     * @param int|string $id
     * @return UserIdentity|IdentityInterface
     */
    public static function findIdentity($id)
    {
        if ($id !== 'test') {
            return null;
        }
        return new static();
    }

    /**
     * @param mixed $token
     * @param null $type
     * @return UserIdentity|IdentityInterface
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        if (static::$token !== $token) {
            return null;
        }

        return new static();
    }

    /**
     * @return int|string
     */
    public function getId()
    {
        return 'test';
    }

    /**
     * @return string|void
     * @throws NotSupportedException
     */
    public function getAuthKey()
    {
        throw new NotSupportedException();
    }

    /**
     * @param string $authKey
     * @return bool|void
     * @throws NotSupportedException
     */
    public function validateAuthKey($authKey)
    {
        throw new NotSupportedException();
    }
}
