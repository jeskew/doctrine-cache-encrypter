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
    /** @var string */
    private $cipher;

    /**
     * @param Cache $decorated
     * @param mixed $cert
     * @param mixed $key
     * @param string|null $passphrase
     * @param string $cipher
     *
     * @throws IAE If either key is not an OpenSSL Key resource.
     */
    public function __construct(
        Cache $decorated,
        $cert,
        $key,
        $passphrase = null,
        $cipher = 'aes-256-ecb'
    ) {
        $this->publicKey = @openssl_pkey_get_public($cert);
        if (!$this->validateOpenSslKey($this->publicKey)) {
            throw new IAE('Unable to create public key from provided'
                . ' certificate. Certificate must be a valid x509 certificate,'
                . ' a PEM encoded certificate, or a path to a file containing a'
                . ' PEM encoded certificate.');
        }

        $this->privateKey = @openssl_pkey_get_private($key, $passphrase);
        if (!$this->validateOpenSslKey($this->privateKey)) {
            throw new IAE('Unable to create private key from provided key. Key'
                . ' must be a PEM encoded private key or a path to a file'
                . ' containing a PEM encoded private key.');
        }

        $this->decorated = $decorated;
        $this->cipher = $cipher;
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
        if (isset($stored['data']) && isset($stored['key'])) {
            openssl_open(
                base64_decode($stored['data']),
                $decrypted,
                base64_decode($stored['key']),
                $this->privateKey,
                $this->cipher
            );
            return unserialize($decrypted);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function save($id, $data, $ttl = 0)
    {
        openssl_seal(
            serialize($data),
            $encrypted,
            $keys,
            array($this->publicKey),
            $this->cipher
        );

        return $this->decorated
            ->save(
                $id,
                array(
                    'data' => base64_encode($encrypted),
                    'key' => base64_encode($keys[0]),
                ),
                $ttl
            );
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

    private function validateOpenSslKey($key)
    {
        return is_resource($key) && 'OpenSSL key' === get_resource_type($key);
    }
}
