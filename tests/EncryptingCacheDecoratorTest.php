<?php
namespace Jsq\Cache;

use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\Cache\Cache;
use Doctrine\Common\Cache\FilesystemCache;

abstract class EncryptingCacheDecoratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject|Cache
     */
    protected $decorated;

    /**
     * @var EncryptingDecorator
     */
    protected $instance;

    /**
     * @var FilesystemCache
     */
    protected $fsCache;

    public function setUp()
    {
        $this->decorated = $this->getMock('Doctrine\Common\Cache\Cache');
        $this->instance = $this->getInstance($this->decorated);
        $this->fsCache = new FilesystemCache(sys_get_temp_dir().'/'.uniqid());
    }

    public function tearDown()
    {
        $this->fsCache->deleteAll();
    }

    public function testProxiesDeleteCallsToDecoratedCache()
    {
        $id = uniqid(time());

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
        $id = uniqid(time());

        $this->decorated->expects($this->once())
            ->method('save')
            ->with(
                $this->equalTo($id),
                $this->callback(function ($arg) use ($data) {
                    return $arg !== $data
                        && $arg instanceof EncryptedValue
                        && $data !== $arg->getCipherText();
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
        $instance = $this->getInstance($this->fsCache);
        $id = uniqid(time());

        $instance->save($id, $data, 0);

        $this->assertNotEquals($data, $this->fsCache->fetch($id));
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
        $id = uniqid(time());

        $decorated->save($id, $data);

        $this->assertEquals($data, $decorated->fetch($id));
        $this->assertFalse($instance->fetch($id));
    }

    public function testContainsReturnsFalseWhenDecoratedCacheHasNoData()
    {
        $instance = $this->getInstance(new ArrayCache);
        $id = uniqid(time());

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
        $id = uniqid(time());

        $decorated->save($id, $data);
        $this->assertTrue($decorated->contains($id));
        $this->assertFalse($instance->contains($id));
    }

    public function cacheableDataProvider()
    {
        return [
            [1],
            ['string'],
            [['key' => 'value']],
            [['one', 2, 3.0]],
            [new \ArrayObject()],
            [[
                'one' => str_repeat('x', 1024*1024),
                'two' => str_repeat('y', 1024*1024),
                'three' => str_repeat('z', 1024*1024),
            ]],
        ];
    }

    /**
     * @param Cache $decorated
     * @return EncryptingDecorator
     */
    abstract protected function getInstance(Cache $decorated);
}
