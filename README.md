# Doctrine Cache Encrypter

[![Build Status](https://travis-ci.org/jeskew/doctrine-cache-encrypter.svg?branch=master)](https://travis-ci.org/jeskew/doctrine-cache-encrypter)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Apache 2 License](https://img.shields.io/packagist/l/jeskew/doctrine-cache-encrypter.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0.html)

Having to encrypt your data at rest shouldn't keep you from using the open-source
tools you know and love. If you have data that needs a higher degree of security
than the rest of your cache, you can store and access it via an 
`EncryptingCacheDecorator`.

First, create your Doctrine-based cache as you normally would:
```php
$cache = new \Doctrine\Common\Cache\RedisCache($redisClient);
```

Second, wrap your cache with an encrypting decorator:
```php
$encryptedCache = new \Jeskew\EncryptingCacheDecorator(
    $cache,
    'file:///path/to/certificate.pem',
    'file:///path/to/private/key.pem'
);
```

> The certificate can be a valid x509 certificate, a path to a PEM-encoded
certificate file (the path must be prefaced with `file://`), or a PEM-encoded
certificate string. The private key can be a path to a PEM-encoded private key
file (the path must be prefaced with `file://`), or a PEM-encoded certificate string.

Then use your `$cache` and `$encryptedCache` like you normally would:
```php
$cache->save('normal_cache_data', 'Totally normal!');

$encryptedCache->save('api_keys', $keys);
```

Though your regular cache and encrypted cache share a storage layer and a
keyspace, they will not be able to read each other's data. The `$encryptedCache`
will return `false` if asked to read unencrypted data, and the regular `$cache`
will return gibberish if asked to read encrypted data.

### What if my private key has a passphrase? And what if I don't like your choice of cipher?

You can provide an array of options as a fourth parameter to the
`EncryptingCacheDecorator`'s constructor. You can use it to override the default
passphrase (`null`) or the default cipher (`AES-256-ECB`). Data is encrypted
using `openssl_seal`, which only supports `RC4` and `ECB`-based ciphers.
