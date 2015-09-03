<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\Cache\Cache;

/**
 * @requires extension openssl
 */
class EncryptingCacheDecoratorTest extends \PHPUnit_Framework_TestCase
{
    /** @var string */
    private static $certificate;
    /** @var string */
    private static $key;
    /** @var resource */
    private static $pKey;
    /** @var \PHPUnit_Framework_MockObject_MockObject|Cache */
    private $decorated;
    /** @var EncryptingCacheDecorator */
    private $instance;

    public static function setUpBeforeClass()
    {
        self::setUpCertAndKey();
    }

    public function setUp()
    {
        $this->decorated = $this->getMock('Doctrine\Common\Cache\Cache');
        $this->instance = new EncryptingCacheDecorator(
            $this->decorated,
            self::getCertificate(),
            self::getKey()
        );
    }

    public static function tearDownAfterClass()
    {
        // clean up the key pair
        openssl_pkey_free(self::$pKey);
    }

    /**
     * @dataProvider invalidParameterProvider
     *
     * @param $certificate
     * @param $key
     *
     * @expectedException \InvalidArgumentException
     */
    public function testVerifiesCertificateAndKey($certificate, $key)
    {
        new EncryptingCacheDecorator($this->decorated, $certificate, $key);
    }

    public function invalidParameterProvider()
    {
        return array(
            array('not a certificate', 'not a PEM-formatted key'),
            array(self::getCertificate(), 'not a PEM-formatted key'),
            array('not a certificate', self::getKey()),
        );
    }

    public function testProxiesContainsCallsToDecoratedCache()
    {
        $id = microtime();

        $this->decorated->expects($this->once())
            ->method('contains')
            ->with($id);
        $this->instance->contains($id);
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
        $privateKey = self::$pKey;
        $id = microtime();

        $this->decorated->expects($this->once())
            ->method('save')
            ->with(
                $this->equalTo($id),
                $this->callback(function ($arg) use ($privateKey, $data) {
                    if ($arg == $data) {
                        return false;
                    }

                    openssl_private_decrypt($arg['data'], $decrypted, $privateKey);
                    return unserialize($decrypted) == $data;
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
    public function testDecryptsDataFetchedDecoratedCache($data)
    {
        $this->decorated = new ArrayCache;
        $this->instance = new EncryptingCacheDecorator(
            $this->decorated,
            self::getCertificate(),
            self::getKey()
        );
        $id = microtime();

        $this->instance
            ->save($id, $data, 0);
        $this->assertNotEquals($data, $this->decorated->fetch($id));
        $this->assertEquals($data, $this->instance->fetch($id));
    }

    public function testReturnsFalseWhenFetchCalledWithUnrecognizedKey()
    {
        $this->assertFalse($this->instance->fetch('Kalamazoo'));
    }

    public function cacheableDataProvider()
    {
        return array(
            array(1),
            array('string'),
            array(array('key' => 'value')),
            array(array('one', 2, 3.0)),
            array(new \ArrayObject()),
        );
    }

    private static function setUpCertAndKey()
    {
        if (empty(self::$pKey)) {
            // create a new key pair
            self::$pKey = openssl_pkey_new();

            // extract the private key
            openssl_pkey_export(self::$pKey, self::$key);

            // extract the public key
            $csr = openssl_csr_new(array(), self::$pKey);
            $x509 = openssl_csr_sign($csr, null, self::$pKey, 1);
            openssl_x509_export($x509, self::$certificate);
            openssl_x509_free($x509);
        }
    }

    private static function getCertificate()
    {
        self::setUpCertAndKey();

        return self::$certificate;
    }

    private static function getKey()
    {
        self::setUpCertAndKey();

        return self::$key;
    }
}
