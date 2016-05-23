<?php
namespace Jsq\Cache\IronEncryption;

use Doctrine\Common\Cache\Cache;
use Jsq\Cache\EncryptingCacheDecoratorTest;
use Iron\Password;

class DecoratorTest extends EncryptingCacheDecoratorTest
{
    public function cacheableDataProvider()
    {
        $toReturn = [];

        // Iron can only transparently round-trip items that can be losslessly
        // represented as JSON, so boot test case containing an object
        foreach (parent::cacheableDataProvider() as $data) {
            $containsObjects = false;
            array_walk_recursive($data, function ($leaf) use (&$containsObjects) {
                if (is_object($leaf)) {
                    $containsObjects = true;
                }
            });

            if (!$containsObjects) {
                $toReturn []= $data;
            }
        }

        return $toReturn;
    }

    protected function getInstance(Cache $decorated)
    {
        return new Decorator($decorated, str_repeat('x', Password::MIN_LENGTH));
    }
}
