# Doctrine Cache Encrypter

[![Build Status](https://travis-ci.org/jeskew/doctrine-cache-encrypter.svg?branch=master)](https://travis-ci.org/jeskew/doctrine-cache-encrypter)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Apache 2 License](https://img.shields.io/packagist/l/jeskew/doctrine-cache-encrypter.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Total Downloads](https://img.shields.io/packagist/dt/jeskew/doctrine-cache-encrypter.svg?style=flat)](https://packagist.org/packages/jeskew/doctrine-cache-encrypter)

Having to encrypt your data at rest shouldn't keep you from using the open-source
tools you know and love. If you have data that needs a higher degree of security
than the rest of your cache, you can store and access it via an 
`EncryptingCacheDecorator`.

## Caveats

Encryption and decryption are both expensive operations, and frequent reads from
an encrypted data store can quickly become a bottleneck in otherwise performant
applications. Use encrypted caches sparingly (i.e., **do not** use an encrypting
decorator around your Doctrine Annotations cache).

## Usage

First, create your Doctrine-based cache as you normally would:
```php
$cache = new \Doctrine\Common\Cache\RedisCache($redisClient);
```

Second, wrap your cache with an encrypting decorator:
```php
$encryptedCache = new \Jeskew\Cache\EncryptingCacheDecorator(
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

You can provide an array of options as a fourth parameter to the
`EncryptingCacheDecorator`'s constructor. You can use it to override the default
passphrase (`null`) or the default cipher (`AES-256-ECB`). Data is encrypted
using `openssl_seal`, which only supports `RC4` and `ECB`-mode ciphers.

## Is AES-256-ECB sufficiently secure for my needs?

AES-256 is approved by the NSA to protect top secret information, but its ECB
mode can leave plaintext data patterns in encrypted ciphertext. [This Stack
Exchange answer](http://crypto.stackexchange.com/a/20946/27519) demonstrates
how. However, because `openssl_seal` uses a random key each time it is called,
this will only leak patterns within a **single** cache entry, not across
multiple cache entries.

If attackers being able to detect patterns in your encrypted plaintext is
unacceptable, you can layer two instances of `EncryptingCacheDecorator` over
your cache, each with a different cipher. `RC4` is a broken cipher that should
not be used on its own but can be counted on to scramble your input.
```php
use Doctrine\Common\Cache\RedisCache;
use Jeskew\Cache\EncryptingCacheDecorator;

$cache = new RedisCache($redisClient);
$encryptedCache = new EncryptingCacheDecorator(
    new EncryptingCacheDecorator(
        $cache,
        'file:///path/to/certificate.pem',
        'file:///path/to/private/key.pem',
        ['cipher' => 'RC4']
    ),
    'file:///path/to/certificate.pem',
    'file:///path/to/private/key.pem'
);
```

## Do I really need to decrypt the same key multiple times?

Decryption is computationally expensive. If you need to access the same
sensitive data multiple times in the same process, you might want to layer
an in-memory cache on top of your encrypted cache using Doctrine's `ChainCache`.
```php
use Doctrine\Common\Cache\ArrayCache;
use Doctrine\Common\Cache\ChainCache;

$cache = new ChainCache([
    new ArrayCache,
    $encryptedCache
]);

// this will read from the encrypted cache and save to the ArrayCache
$superSensitive = $cache->fetch('super_sensitive');

// this will read already-decrypted data from the ArrayCache
$superSensitive = $cache->fetch('super_sensitive');
```

This can help if you're required to encrypt data at rest but are under no such
restrictions regarding data that resides purely in volatile memory.
