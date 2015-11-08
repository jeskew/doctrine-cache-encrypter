<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;
use InvalidArgumentException as IAE;

class PkiEncryptionDecorator extends EncryptingCacheDecorator
{
    /** @var resource[] */
    private $publicKeys;
    /** @var string */
    private $publicKeyFingerprint;
    /** @var resource */
    private $privateKey;
    /** @var string */
    private $cipher;

    /**
     * @param Cache $decorated
     * @param array $certs
     * @param mixed $key
     * @param string|null $passphrase
     * @param string $cipher
     *
     * @throws IAE If OpenSSL keys cannot be extracted from $cert and $key.
     */
    public function __construct(
        Cache $decorated,
        array $certs,
        $key,
        $passphrase = null,
        $cipher = 'aes-256-ecb'
    ) {
        parent::__construct($decorated);
        $this->setPrivateKey($key, $passphrase);
        $this->cipher = $cipher;
        foreach ($certs as $cert) {
            $this->addPublicKey($cert);
        }
    }

    public function __destruct()
    {
        foreach ($this->publicKeys as $publicKey) {
            openssl_free_key($publicKey);
        }
        openssl_free_key($this->privateKey);
    }

    protected function isDataDecryptable($data, $id)
    {
        return is_array($data)
            && $this->arrayHasKeys($data, ['encrypted', 'keys', 'cipher', 'mac'])
            && isset($data['keys'][$this->publicKeyFingerprint])
            && $data['cipher'] === $this->cipher
            && $data['mac'] === $this->hmac($data['encrypted'], $id);
    }

    protected function encrypt($data, $id)
    {
        $data = serialize($data);
        openssl_seal($data, $encrypted, $keys, $this->publicKeys, $this->cipher);
        $encrypted = base64_encode($encrypted);

        return [
            'encrypted' => $encrypted,
            'keys' => array_combine(
                array_keys($this->publicKeys),
                array_map('base64_encode', $keys)
            ),
            'cipher' => $this->cipher,
            'mac' => $this->hmac($encrypted, $id),
        ];
    }

    protected function decrypt($data)
    {
        openssl_open(
            base64_decode($data['encrypted']),
            $decrypted,
            base64_decode($data['keys'][$this->publicKeyFingerprint]),
            $this->privateKey,
            $this->cipher
        );

        return unserialize($decrypted);
    }

    private function addPublicKey($cert)
    {
        $publicKey = @openssl_pkey_get_public($cert);
        if (!$this->validateOpenSslKey($publicKey)) {
            throw new IAE('Unable to create public key from provided'
                . ' certificate. Certificate must be a valid x509 certificate,'
                . ' a PEM encoded certificate, or a path to a file containing a'
                . ' PEM encoded certificate.');
        }

        $this->publicKeys[$this->getPublicKeyPrint($publicKey)] = $publicKey;
    }

    private function getPublicKeyPrint($key)
    {
        return md5(openssl_pkey_get_details($key)['key']);
    }

    private function setPrivateKey($key, $passphrase)
    {
        $this->privateKey = @openssl_pkey_get_private($key, $passphrase);
        if (!$this->validateOpenSslKey($this->privateKey)) {
            throw new IAE('Unable to create private key from provided key. Key'
                . ' must be a PEM encoded private key or a path to a file'
                . ' containing a PEM encoded private key.');
        }

        $this->publicKeyFingerprint = $this->getPublicKeyPrint($this->privateKey);
    }

    private function validateOpenSslKey($key)
    {
        return is_resource($key) && 'OpenSSL key' === get_resource_type($key);
    }
}
