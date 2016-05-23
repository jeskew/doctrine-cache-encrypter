<?php
namespace Jsq\Cache\IronEncryption;

use Doctrine\Common\Cache\Cache;
use Jsq\Cache\EncryptionStatsTrait;
use Iron;
use Iron\PasswordInterface;
use Iron\Token;
use Throwable;

class Decorator implements Cache
{
    use EncryptionStatsTrait;

    /** @var Cache */
    private $decorated;
    /** @var Iron\Iron */
    private $iron;
    /** @var PasswordInterface */
    private $password;

    public function __construct(
        Cache $decorated,
        $password,
        $cipher = Iron\Iron::DEFAULT_ENCRYPTION_METHOD
    ) {
        if (!class_exists(Iron\Iron::class)) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('You must install'
                . ' jsq/iron-php to use the Iron decorator.');
            // @codeCoverageIgnoreEnd
        }

        $this->decorated = $decorated;
        $this->password = Iron\normalize_password($password);
        $this->iron = new Iron\Iron($cipher);
    }

    public function fetch($id)
    {
        try {
            return $this->returnHit($this->callAndTime(function () use ($id) {
                return json_decode($this->iron->decryptToken(
                    Token::fromSealed(
                        $this->password,
                        $this->decorated->fetch($id)
                    ),
                    $this->password
                ), true);
            }));
        } catch (Throwable $e) {
            return $this->returnMiss(false);
        }
    }

    public function contains($id)
    {
        try {
            Token::fromSealed(
                $this->password,
                $this->decorated->fetch($id)
            );
            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    public function save($id, $data, $ttl = 0)
    {
        return $this->decorated->save(
            $id,
            (string) $this->callAndTime(function () use ($data, $ttl) {
                return $this->iron
                    ->encrypt($this->password, json_encode($data), $ttl);
            }),
            $ttl
        );
    }

    public function delete($id)
    {
        return $this->decorated->delete($id);
    }

    public function getStats()
    {
        return $this->getEncryptionStats($this->decorated->getStats() ?: []);
    }
}
