<?php
namespace Jsq\Cache;

use Doctrine\Common\Cache\Cache;

abstract class EncryptingDecorator implements Cache
{
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
            return $this->decrypt($stored);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function save($id, $data, $ttl = 0)
    {
        return $this->decorated
            ->save($id, $this->encrypt($data, $id), $ttl);
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
        return $this->decorated
            ->getStats();
    }

    /**
     * {@inheritdoc}
     */
    public function delete($id)
    {
        return $this->decorated
            ->delete($id);
    }

    protected function hmac($encrypted, $id)
    {
        return hash_hmac('sha256', $encrypted, $id);
    }

    abstract protected function encrypt($data, $id);

    abstract protected function decrypt($data);

    abstract protected function isDataDecryptable($data, $id);

    protected function generateIv($method)
    {
        return openssl_random_pseudo_bytes(
            openssl_cipher_iv_length($method)
        );
    }

    protected function encryptString($string, $method, $key, $iv)
    {
        return openssl_encrypt($string, $method, $key, 0, $iv);
    }

    protected function decryptString($string, $method, $key, $iv)
    {
        return openssl_decrypt($string, $method, $key, 0, $iv);
    }
}
