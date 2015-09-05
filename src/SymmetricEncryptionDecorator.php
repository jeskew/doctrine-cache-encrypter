<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;

class SymmetricEncryptionDecorator extends EncryptingCacheDecorator
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

    protected function isDataDecryptable($data)
    {
        return is_array($data)
            && $this->arrayHasKeys($data, array('encrypted', 'iv', 'cipher'))
            && $data['cipher'] === $this->cipher;
    }

    protected function encrypt($data)
    {
        $iv = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length($this->cipher)
        );

        return array(
            'cipher' => $this->cipher,
            'iv' => $iv,
            'encrypted' => openssl_encrypt(
                serialize($data),
                $this->cipher,
                $this->passphrase,
                0,
                $iv
            ),
        );
    }

    protected function decrypt($data)
    {
        return unserialize(openssl_decrypt(
            $data['encrypted'],
            $this->cipher,
            $this->passphrase,
            0,
            $data['iv']
        ));
    }
}
