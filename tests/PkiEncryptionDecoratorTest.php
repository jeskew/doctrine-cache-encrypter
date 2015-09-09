<?php
namespace Jeskew\Cache;

use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\Cache\Cache;

class PkiEncryptionDecoratorTest extends EncryptingCacheDecoratorTest
{
    /** @var string */
    private static $certificate;
    /** @var string */
    private static $key;

    protected function getInstance(Cache $decorated)
    {
        return new PkiEncryptionDecorator(
            $decorated,
            [self::getCertificate()],
            self::getKey()
        );
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
        new PkiEncryptionDecorator($this->decorated, $certificate, $key);
    }

    public function invalidParameterProvider()
    {
        return [
            [['not a certificate'], 'not a PEM-formatted key'],
            [[self::getCertificate()], 'not a PEM-formatted key'],
            [['not a certificate'], self::getKey()],
        ];
    }

    public function testEncryptsDataAgainstMultipleKeys()
    {
        $certPairs = [[
            'public' => self::getCertificate(),
            'private' => self::getKey(),
        ]];
        self::clearCertAndKey();
        $certPairs []= [
            'public' => self::getCertificate(),
            'private' => self::getKey(),
        ];

        $decorated = new ArrayCache;
        $instance1 = new PkiEncryptionDecorator(
            $decorated,
            array_map(function (array $pair) { return $pair['public']; }, $certPairs),
            $certPairs[0]['private']
        );
        $instance2 = new PkiEncryptionDecorator(
            $decorated,
            array_map(function (array $pair) { return $pair['public']; }, $certPairs),
            $certPairs[1]['private']
        );

        $instance1->save('foo', 'bar');
        $this->assertSame('bar', $instance1->fetch('foo'));
        $this->assertSame('bar', $instance2->fetch('foo'));
    }

    private static function clearCertAndKey()
    {
        self::$certificate = null;
        self::$key = null;
    }

    private static function setUpCertAndKey()
    {
        if (empty(self::$certificate) || empty(self::$key)) {
            // create a new key pair
            $pKey = openssl_pkey_new();

            // extract the private key
            openssl_pkey_export($pKey, self::$key);

            // extract the public key
            $csr = openssl_csr_new([], $pKey);
            $x509 = openssl_csr_sign($csr, null, $pKey, 1);
            openssl_x509_export($x509, self::$certificate);

            // clean up the created artifacts
            openssl_x509_free($x509);
            openssl_pkey_free($pKey);
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
