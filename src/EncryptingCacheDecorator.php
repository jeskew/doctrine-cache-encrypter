<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;
use InvalidArgumentException as IAE;

class EncryptingCacheDecorator implements Cache
{
    /** @var Cache */
    private $decorated;
    /** @var resource */
    private $publicKey;
    /** @var resource */
    private $privateKey;

    /**
     * @param Cache $decorated
     * @param mixed $cert
     * @param mixed $key
     * @param string|null $password
     *
     * @throws IAE If either key is not an OpenSSL Key resource.
     */
    public function __construct(Cache $decorated, $cert, $key, $password = null)
    {
        $this->publicKey = @openssl_pkey_get_public($cert);
        if (!is_resource($this->publicKey)
            || 'OpenSSL key' !== get_resource_type($this->publicKey)
        ) {
            throw new IAE('Unable to create public key from provided'
                . ' certificate. Certificate must be a valid x509 certificate,'
                . ' a PEM encoded certificate, or a path to a file containing a'
                . ' PEM encoded certificate.');
        }

        $this->privateKey = @openssl_pkey_get_private($key, $password);
        if (!is_resource($this->privateKey)
            || 'OpenSSL key' !== get_resource_type($this->publicKey)
        ) {
            throw new IAE('Unable to create private key from provided key. Key'
                . ' must be a PEM encoded private key or a path to a file'
                . ' containing a PEM encoded private key.');
        }

        $this->decorated = $decorated;
    }

    public function __destruct()
    {
        openssl_free_key($this->publicKey);
        openssl_free_key($this->privateKey);
    }

    /**
     * {@inheritdoc}
     */
    public function fetch($id)
    {
        $stored = $this->decorated->fetch($id);
        if (isset($stored['data'])) {
            openssl_private_decrypt($stored['data'], $decrypted, $this->privateKey);
            return unserialize($decrypted);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function save($id, $data, $ttl = 0)
    {
        openssl_public_encrypt(serialize($data), $encrypted, $this->publicKey);

        return $this->decorated
            ->save($id, array('data' => $encrypted), $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public function contains($id)
    {
        return $this->decorated
            ->contains($id);
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
}
