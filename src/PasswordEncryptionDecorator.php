<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;

class PasswordEncryptionDecorator extends EncryptingCacheDecorator
{
    /** @var string */
    private $cipher;
    /** @var string */
    private $passphrase;

    public function __construct(
        Cache $decorated,
        $passphrase,
        $cipher = 'aes-256-cbc'
    ) {
        parent::__construct($decorated);
        $this->passphrase = $passphrase;
        $this->cipher = $cipher;
    }

    protected function isDataDecryptable($data, $id)
    {
        return is_array($data)
            && $this->arrayHasKeys($data, ['encrypted', 'iv', 'cipher', 'mac'])
            && $data['cipher'] === $this->cipher
            && $data['mac'] === $this->hmac($data['encrypted'], $id);
    }

    protected function encrypt($data, $id)
    {
        $iv = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length($this->cipher)
        );
        $encrypted = openssl_encrypt(
            serialize($data),
            $this->cipher,
            $this->passphrase,
            0,
            $iv
        );

        return [
            'cipher' => $this->cipher,
            'iv' => base64_encode($iv),
            'encrypted' => $encrypted,
            'mac' => $this->hmac($encrypted, $id),
        ];
    }

    protected function decrypt($data)
    {
        return unserialize(openssl_decrypt(
            $data['encrypted'],
            $this->cipher,
            $this->passphrase,
            0,
            base64_decode($data['iv'])
        ));
    }
}
