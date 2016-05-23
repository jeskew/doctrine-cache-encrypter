<?php
namespace Jsq\Cache;

use Doctrine\Common\Cache\Cache;

abstract class EncryptingDecorator implements Cache
{
    use EncryptionStatsTrait;

    /** @var Cache */
    protected $decorated;

    /**
     * @param Cache $decorated
     */
    public function __construct(Cache $decorated)
    {
        $this->decorated = $decorated;
    }

    /**
     * {@inheritdoc}
     */
    public function fetch($id)
    {
        $stored = $this->decorated->fetch($id);
        if ($this->isDataDecryptable($stored, $id)) {
            return $this->returnHit(
                $this->callAndTime([$this, 'decrypt'], [$stored])
            );
        }

        return $this->returnMiss(false);
    }

    /**
     * {@inheritdoc}
     */
    public function save($id, $data, $ttl = 0)
    {
        return $this->decorated->save(
            $id,
            $this->callAndTime([$this, 'encrypt'], [$data, $id]),
            $ttl
        );
    }

    /**
     * {@inheritdoc}
     */
    public function contains($id)
    {
        if ($stored = $this->decorated->fetch($id)) {
            return $this->isDataDecryptable($stored, $id);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStats()
    {
        return $this->getEncryptionStats($this->decorated->getStats() ?: []);
    }

    /**
     * {@inheritdoc}
     */
    public function delete($id)
    {
        return $this->decorated
            ->delete($id);
    }

    protected function hmac(string $encrypted, string $id): string
    {
        return hash_hmac('sha256', $encrypted, $id);
    }

    protected function generateIv(string $method): string
    {
        return random_bytes(openssl_cipher_iv_length($method));
    }

    protected function encipher(
        string $string,
        string $method,
        string $key,
        string $iv
    ): string {
        return openssl_encrypt($string, $method, $key, 0, $iv);
    }

    protected function decipher(
        string $string,
        string $method,
        string $key,
        string $iv
    ): string {
        return openssl_decrypt($string, $method, $key, 0, $iv);
    }

    abstract protected function encrypt($data, string $id): EncryptedValue;

    abstract protected function decrypt($data);

    abstract protected function isDataDecryptable($data, string $id): bool;
}
