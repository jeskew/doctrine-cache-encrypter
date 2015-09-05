<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;

abstract class EncryptingCacheDecorator implements Cache
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
        if ($this->isDataDecryptable($stored)) {
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
            ->save($id, $this->encrypt($data), $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public function contains($id)
    {
        if ($stored = $this->decorated->fetch($id)) {
            return $this->isDataDecryptable($stored);
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

    protected function arrayHasKeys(array $input, array $keys)
    {
        foreach ($keys as $key) {
            if (empty($input[$key])) {
                return false;
            }
        }

        return true;
    }

    abstract protected function encrypt($data);

    abstract protected function decrypt($data);

    abstract protected function isDataDecryptable($data);
}
