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
        $cipher = 'aes256'
    ) {
        parent::__construct($decorated);
        $this->passphrase = $passphrase;
        $this->cipher = $cipher;
    }

    protected function isDataDecryptable($data)
    {
        return is_array($data)
            && $this->arrayHasKeys($data, ['encrypted', 'iv', 'cipher'])
            && $data['cipher'] === $this->cipher;
    }

    protected function encrypt($data)
    {
        $iv = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length($this->cipher)
        );

        return [
            'cipher' => $this->cipher,
            'iv' => base64_encode($iv),
            'encrypted' => openssl_encrypt(
                serialize($data),
                $this->cipher,
                $this->passphrase,
                0,
                $iv
            ),
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
