<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;
use InvalidArgumentException as IAE;

class AsymmetricEncryptionDecorator extends EncryptingCacheDecorator
{
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
     * @throws IAE If OpenSSL keys cannot be extracted from $cert and $key.
     */
    public function __construct(
        Cache $decorated,
        $cert,
        $key,
        $passphrase = null,
        $cipher = 'aes-256-ecb'
    ) {
        parent::__construct($decorated);
        $this->setPublicKey($cert);
        $this->setPrivateKey($key, $passphrase);
        $this->cipher = $cipher;
    }

    public function __destruct()
    {
        openssl_free_key($this->publicKey);
        openssl_free_key($this->privateKey);
    }

    protected function isDataDecryptable($data)
    {
        return is_array($data)
            && $this->arrayHasKeys($data, array('encrypted', 'key', 'cipher'))
            && $data['cipher'] === $this->cipher;
    }

    protected function encrypt($data)
    {
        openssl_seal(
            serialize($data),
            $encrypted,
            $keys,
            array($this->publicKey),
            $this->cipher
        );

        return array(
            'encrypted' => base64_encode($encrypted),
            'key' => base64_encode($keys[0]),
            'cipher' => $this->cipher,
        );
    }

    protected function decrypt($data)
    {
        openssl_open(
            base64_decode($data['encrypted']),
            $decrypted,
            base64_decode($data['key']),
            $this->privateKey,
            $this->cipher
        );

        return unserialize($decrypted);
    }

    private function setPublicKey($cert)
    {
        $this->publicKey = @openssl_pkey_get_public($cert);
        if (!$this->validateOpenSslKey($this->publicKey)) {
            throw new IAE('Unable to create public key from provided'
                . ' certificate. Certificate must be a valid x509 certificate,'
                . ' a PEM encoded certificate, or a path to a file containing a'
                . ' PEM encoded certificate.');
        }
    }

    private function setPrivateKey($key, $passphrase)
    {
        $this->privateKey = @openssl_pkey_get_private($key, $passphrase);
        if (!$this->validateOpenSslKey($this->privateKey)) {
            throw new IAE('Unable to create private key from provided key. Key'
                . ' must be a PEM encoded private key or a path to a file'
                . ' containing a PEM encoded private key.');
        }
    }

    private function validateOpenSslKey($key)
    {
        return is_resource($key) && 'OpenSSL key' === get_resource_type($key);
    }
}
