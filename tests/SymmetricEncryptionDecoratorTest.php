<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\Cache;

class SymmetricEncryptionDecoratorTest extends EncryptingCacheDecoratorTest
{
    protected function getInstance(Cache $decorated)
    {
        return new SymmetricEncryptionDecorator($decorated, 'abc123');
    }
}
