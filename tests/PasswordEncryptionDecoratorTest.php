<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;

class PasswordEncryptionDecoratorTest extends EncryptingCacheDecoratorTest
{
    protected function getInstance(Cache $decorated)
    {
        return new PasswordEncryptionDecorator($decorated, 'abc123');
    }
}
