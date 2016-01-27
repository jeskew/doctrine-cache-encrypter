<?php
namespace Jsq\Cache\EnvelopeEncryption;

use Jsq\Cache\EncryptedValue;

class Value extends EncryptedValue
{
    /** @var string */
    private $envelopeKey;
    /** @var string */
    private $signature;

    /**
     * @param string $cipherText
     * @param string $method
     * @param string $iv
     * @param string $key
     * @param string $signature
     */
    public function __construct($cipherText, $method, $iv, $key, $signature)
    {
        parent::__construct($cipherText, $method, $iv);
        $this->envelopeKey = $key;
        $this->signature = $signature;
    }

    public function jsonSerialize()
    {
        return parent::jsonSerialize() + [
            'key' => base64_encode($this->envelopeKey),
            'signature' => base64_encode($this->signature),
        ];
    }

    public function unserialize($serialized)
    {
        parent::unserialize($serialized);

        $data = json_decode($serialized);
        $this->envelopeKey = base64_decode($data->key);
        $this->signature = base64_decode($data->signature);
    }

    /**
     * @return string
     */
    public function getEnvelopeKey()
    {
        return $this->envelopeKey;
    }

    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }
}
