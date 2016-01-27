<?php
namespace Jsq\Cache\EnvelopeEncryption;

use Doctrine\Common\Cache\Cache;
use InvalidArgumentException as IAE;
use Jsq\Cache\EncryptingDecorator;

class Decorator extends EncryptingDecorator
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
        $cipher = 'aes-256-cbc'
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

    protected function isDataDecryptable($data, $id)
    {
        return $data instanceof Value
            && $this->validateSignature(
                $id . $data->getCipherText(),
                $data->getSignature()
            );
    }

    protected function encrypt($data, $id)
    {
        $key = $this->generateIv($this->cipher);
        $iv = $this->generateIv($this->cipher);
        $cipherText = $this->encryptString(serialize($data), $this->cipher, $key, $iv);

        return new Value(
            $cipherText,
            $this->cipher,
            $iv,
            $this->encryptEnvelopeKey($key),
            $this->signString($id . $cipherText)
        );
    }

    protected function decrypt($data)
    {
        if (!$data instanceof Value) return false;

        return unserialize($this->decryptString(
            $data->getCipherText(),
            $data->getMethod(),
            $this->decryptEnvelopeKey($data->getEnvelopeKey()),
            $data->getInitializationVector()
        ));
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

    private function signString($string)
    {
        openssl_sign($string, $signature, $this->privateKey);

        return $signature;
    }

    private function validateSignature($signed, $signature)
    {
        return openssl_verify($signed, $signature, $this->publicKey);
    }

    private function encryptEnvelopeKey($key)
    {
        openssl_public_encrypt($key, $sealedKey, $this->publicKey);

        return $sealedKey;
    }

    private function decryptEnvelopeKey($sealedKey)
    {
        openssl_private_decrypt($sealedKey, $key, $this->privateKey);

        return $key;
    }
}
