<?php
namespace Jsq\Cache;

use JsonSerializable;
use Serializable;

abstract class EncryptedValue implements JsonSerializable, Serializable
{
    /** @var string */
    private $cipherText;
    /** @var string */
    private $method;
    /** @var string */
    private $initializationVector;

    public function __construct($cipherText, $method, $iv)
    {
        $this->cipherText = $cipherText;
        $this->method = $method;
        $this->initializationVector = $iv;
    }

    public function jsonSerialize()
    {
        return [
            'cipherText' => $this->cipherText,
            'method' => $this->method,
            'iv' => base64_encode($this->initializationVector),
        ];
    }

    public function serialize()
    {
        return json_encode($this->jsonSerialize());
    }

    public function unserialize($serialized)
    {
        $data = json_decode($serialized);
        $this->cipherText = $data->cipherText;
        $this->method = $data->method;
        $this->initializationVector = base64_decode($data->iv);
    }

    /**
     * @return string
     */
    public function getCipherText()
    {
        return $this->cipherText;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * @return string
     */
    public function getInitializationVector()
    {
        return $this->initializationVector;
    }
}
