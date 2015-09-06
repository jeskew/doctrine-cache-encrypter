# Doctrine Cache Encrypter

[![Build Status](https://travis-ci.org/jeskew/doctrine-cache-encrypter.svg?branch=master)](https://travis-ci.org/jeskew/doctrine-cache-encrypter)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jeskew/doctrine-cache-encrypter/?branch=master)
[![Apache 2 License](https://img.shields.io/packagist/l/jeskew/doctrine-cache-encrypter.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Total Downloads](https://img.shields.io/packagist/dt/jeskew/doctrine-cache-encrypter.svg?style=flat)](https://packagist.org/packages/jeskew/doctrine-cache-encrypter)
[![Author](http://img.shields.io/badge/author-@jreskew-blue.svg?style=flat-square)](https://twitter.com/jreskew)

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

> This package provides two cache decorators, one that encrypts data using
a pass phrase and one that does so with public and private keys. The
implementation using a pass phrase is the more performant of the two but
requires that you securely deploy a plaintext password.

First, create your Doctrine-based cache as you normally would:
```php
$cache = new \Doctrine\Common\Cache\RedisCache($redisClient);
```

Second, wrap your cache with an encrypting decorator:
```php
$encryptedCache = new \Jeskew\Cache\PasswordEncryptionDecorator(
    $cache,
    $password,
    $cipher // optional, defaults to 'aes-256-cfb'
);
```

Then use your `$cache` and `$encryptedCache` like you normally would:
```php
$cache->save('normal_cache_data', 'Totally normal!');

$encryptedCache->save('api_keys', $keys);
```

Though your regular cache and encrypted cache share a storage layer and a
keyspace, they will not be able to read each other's data. The `$encryptedCache`
will return `false` if asked to read unencrypted data, and the regular `$cache`
will return gibberish if asked to read encrypted data.

## Encrypting your cache without sharing secrets

If you'd rather not rely on a shared password, the `PkiEncryptionDecorator` can
secure your sensitive cache entries using public/private key pairs. You can
encrypt an entry against multiple public keys, and it will be decryptable by any
of their private counterparts.

```php
$encryptedCache = new \Jeskew\Cache\PkiEncryptionDecorator(
    $cache,
    [
        'file:///path/to/certificate.pem',
        'file:///path/to/other/certificate.pem',
    ],
    'file:///path/to/private/key.pem',
    $passphrase_for_private_key_file, // optional, defaults to null
    $cipher // optional, defaults to 'aes-256-ecb'
);
```

> The certificates can be a valid x509 certificate, a path to a PEM-encoded
certificate file (the path must be prefaced with `file://`), or a PEM-encoded
certificate string. The private key can be a path to a PEM-encoded private key
file (the path must be prefaced with `file://`), or a PEM-encoded certificate string.

## Is AES-256-ECB sufficiently secure for my needs?

AES-256 is approved by the NSA to protect top secret information, but ECB mode
can leave plaintext data patterns in encrypted ciphertext. [This Stack Exchange
answer](http://crypto.stackexchange.com/a/20946/27519) demonstrates how. The
`PkiEncryptionDecorator` relies on `openssl_seal`, which only supports RC4 (a
broken cipher) and the ECB modes of several block ciphers. However, because
`openssl_seal` uses a random key each time it is called, this will only leak
patterns within a **single** cache entry, not across multiple cache entries.

If attackers being able to detect patterns in your encrypted plaintext is
unacceptable, you can layer two encrypting decorators over your cache. Using a
`PasswordEncryptionDecorator` with a hardcoded password and a fast stream cipher
like `RC4` will reliably scramble your input.
```php
use Doctrine\Common\Cache\RedisCache;
use Jeskew\Cache\PasswordEncryptionDecorator;
use Jeskew\Cache\PkiEncryptionDecorator;

$cache = new RedisCache($redisClient);
$encryptedCache = new PkiEncryptionDecorator(
    new PasswordEncryptionDecorator($cache, 'abc123', 'RC4'),
    ['file:///path/to/certificate.pem'],
    'file:///path/to/private/key.pem'
);
```
