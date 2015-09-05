<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\Cache\Cache;

abstract class EncryptingCacheDecoratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject|Cache
     */
    protected $decorated;

    /**
     * @var EncryptingCacheDecorator
     */
    protected $instance;

    public function setUp()
    {
        $this->decorated = $this->getMock('Doctrine\Common\Cache\Cache');
        $this->instance = $this->getInstance($this->decorated);
    }

    public function testProxiesDeleteCallsToDecoratedCache()
    {
        $id = microtime();

        $this->decorated->expects($this->once())
            ->method('delete')
            ->with($id);
        $this->instance->delete($id);
    }

    public function testProxiesFetchStatCallsToDecoratedCache()
    {
        $this->decorated->expects($this->once())
            ->method('getStats')
            ->with();
        $this->instance->getStats();
    }

    /**
     * @dataProvider cacheableDataProvider
     *
     * @param mixed $data
     */
    public function testEncryptsDataBeforePassingToDecoratedCache($data)
    {
        $id = microtime();

        $this->decorated->expects($this->once())
            ->method('save')
            ->with(
                $this->equalTo($id),
                $this->callback(function ($arg) use ($data) {
                    return $arg != $data;
                }),
                $this->equalTo(0)
            );
        $this->instance
            ->save($id, $data, 0);
    }

    /**
     * @dataProvider cacheableDataProvider
     *
     * @param mixed $data
     */
    public function testDecryptsDataFetchedFromDecoratedCache($data)
    {
        $decorated = new ArrayCache;
        $instance = $this->getInstance($decorated);
        $id = microtime();

        $instance->save($id, $data, 0);

        $this->assertNotEquals($data, $decorated->fetch($id));
        $this->assertEquals($data, $instance->fetch($id));
    }

    public function testReturnsFalseWhenFetchCalledWithUnrecognizedKey()
    {
        $this->assertFalse($this->instance->fetch('Kalamazoo'));
    }

    /**
     * @dataProvider cacheableDataProvider
     *
     * @param mixed $data
     */
    public function testReturnsFalseWhenFetchRetrievesUnencryptedData($data)
    {
        $decorated = new ArrayCache;
        $instance = $this->getInstance($decorated);
        $id = microtime();

        $decorated->save($id, $data);

        $this->assertEquals($data, $decorated->fetch($id));
        $this->assertFalse($instance->fetch($id));
    }

    public function testContainsReturnsFalseWhenDecoratedCacheHasNoData()
    {
        $decorated = new ArrayCache;
        $instance = $this->getInstance($decorated);
        $id = microtime();

        $this->assertFalse($instance->contains($id));
    }

    /**
     * @dataProvider cacheableDataProvider
     *
     * @param mixed $data
     */
    public function testContainsReturnsFalseWhenKeyHasUnencryptedData($data)
    {
        $decorated = new ArrayCache;
        $instance = $this->getInstance($decorated);
        $id = microtime();

        $decorated->save($id, $data);
        $this->assertTrue($decorated->contains($id));
        $this->assertFalse($instance->contains($id));
    }

    public function cacheableDataProvider()
    {
        return array(
            array(1),
            array('string'),
            array(array('key' => 'value')),
            array(array('one', 2, 3.0)),
            array(new \ArrayObject()),
            array(array(
                'one' => str_repeat('x', 1024*512),
                'two' => str_repeat('y', 1024*512),
                'three' => str_repeat('z', 1024*512),
            )),
        );
    }

    /**
     * @param Cache $decorated
     * @return EncryptingCacheDecorator
     */
    abstract protected function getInstance(Cache $decorated);
}
