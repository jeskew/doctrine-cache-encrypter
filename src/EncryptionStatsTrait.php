<?php
namespace Jsq\Cache;

trait EncryptionStatsTrait
{
    private $hits = 0;
    private $misses = 0;
    private $encryptionTime = 0.0;

    private function getEncryptionStats(array $inner = [])
    {
        return [
            'hits' => $this->hits,
            'misses' => $this->misses,
            'encryption_time' => $this->encryptionTime,
        ] + $inner + [
            'uptime' => null,
            'memory_usage' => null,
            'memory_available' => null,
        ];
    }

    private function callAndTime(callable $func, array $args = [])
    {
        $start = microtime(true);
        $returnable = call_user_func_array($func, $args);
        $this->encryptionTime += microtime(true) - $start;
        return $returnable;
    }

    private function returnHit($hit)
    {
        $this->hits++;
        return $hit;
    }

    private function returnMiss($miss)
    {
        $this->misses++;
        return $miss;
    }
}
