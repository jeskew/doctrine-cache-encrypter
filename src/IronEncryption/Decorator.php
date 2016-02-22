<?php
namespace Jsq\Cache\IronEncryption;

use Doctrine\Common\Cache\Cache;
use Exception;
use Jsq\Cache\EncryptionStatsTrait;
use Jsq\Iron;
use Jsq\Iron\PasswordInterface;
use Jsq\Iron\Token;

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
        $this->decorated = $decorated;
        $this->password = Iron\normalize_password($password);
        $this->iron = new Iron\Iron($cipher);
    }

    public function fetch($id)
    {
        try {
            return $this->returnHit($this->callAndTime(
                [$this->iron, 'decrypt'],
                [$this->password, $this->decorated->fetch($id)]
            ));
        } catch (Exception $e) {
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
        } catch (Exception $e) {
            return false;
        }
    }

    public function save($id, $data, $ttl = 0)
    {
        return $this->decorated->save(
            $id,
            (string) $this->callAndTime(
                [$this->iron, 'encrypt'],
                [$this->password, $data, $ttl]
            ),
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
