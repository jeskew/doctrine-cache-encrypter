<?php
namespace Jsq\Cache\PasswordEncryption;

use Doctrine\Common\Cache\Cache;
use Jsq\Cache\EncryptingCacheDecoratorTest;

class DecoratorTest extends EncryptingCacheDecoratorTest
{
    protected function getInstance(Cache $decorated)
    {
        return new Decorator($decorated, 'abc123');
    }
}
