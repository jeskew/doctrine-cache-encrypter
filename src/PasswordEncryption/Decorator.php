<?php
namespace Jsq\Cache\PasswordEncryption;

use Doctrine\Common\Cache\Cache;
use Jsq\Cache\EncryptedValue;
use Jsq\Cache\EncryptingDecorator;

class Decorator extends EncryptingDecorator
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

    protected function isDataDecryptable($data, string $id): bool
    {
        return $data instanceof Value
            && $data->getMac() === $this->authenticate($id, $data->getCipherText());
    }

    protected function encrypt($data, string $id): EncryptedValue
    {
        $iv = $this->generateIv($this->cipher);
        $cipherText = $this->encipher(
            serialize($data),
            $this->cipher,
            $this->passphrase,
            $iv
        );

        return new Value(
            $cipherText,
            $this->cipher,
            $iv,
            $this->authenticate($id, $cipherText)
        );
    }

    protected function decrypt($data)
    {
        if (!$data instanceof Value) return false;

        return unserialize($this->decipher(
            $data->getCipherText(),
            $data->getMethod(),
            $this->passphrase,
            $data->getInitializationVector()
        ));
    }

    private function authenticate($key, $cipherText)
    {
        return $this->hmac($cipherText, $this->hmac($key, $this->passphrase));
    }
}
