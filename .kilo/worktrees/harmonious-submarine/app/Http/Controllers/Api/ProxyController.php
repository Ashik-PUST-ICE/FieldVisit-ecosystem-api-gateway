<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\Gateway\TokenBroker;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ProxyController extends Controller
{
    public function __construct(private TokenBroker $broker) {}

    // $mode: 'public' | 'user' | 'machine'
    public function forward(Request $req, string $service, string $path = '', string $mode = 'user')
    {
        $cfg = config("gateway.services.$service");
        abort_if(! $cfg, 404, 'Unknown service');

        $cbKey = "cb:$service";
        if ($this->isOpen($cbKey, (int) ($cfg['circuit_ttl'] ?? 30))) {
            return response()->json(['message' => 'Service temporarily unavailable'], 503);
        }

        $method = strtoupper($req->method());
        $base = rtrim($cfg['base_uri'], '/');
        $target = $base.'/'.ltrim($path, '/');
        $timeout = (float) config('gateway.cb.timeout', 3.0);

        // Optional GET cache for non-user modes
        $ttl = ($method === 'GET' && $mode !== 'user') ? (int) ($cfg['cache_ttl'] ?? 0) : 0;
        if ($ttl > 0) {
            $key = "gw:$service:$method:".md5($target.'|'.http_build_query($req->query()));

            return Cache::remember($key, $ttl, fn () => $this->send($req, $target, $method, $timeout, $cbKey, $cfg, $mode, $service));
        }

        return $this->send($req, $target, $method, $timeout, $cbKey, $cfg, $mode, $service);
    }

    private function send(Request $req, string $url, string $method, float $timeout, string $cbKey, array $cfg, string $mode, string $service)
    {
        $client = new Client(['http_errors' => false, 'timeout' => $timeout]);
        $start = microtime(true);

        // Whitelist headers
        $allow = array_flip(config('gateway.forward_headers'));
        $headers = [];
        foreach ($req->headers->all() as $k => $vals) {
            if (isset($allow[strtolower($k)])) {
                $headers[$k] = $vals;
            }
        }
        $headers['Host'] = [parse_url($url, PHP_URL_HOST)];
        if ($rid = $req->header('X-Request-ID')) {
            $headers['X-Request-ID'] = [$rid];
        }
        unset($headers['Cookie']); // never forward cookies

        // Auth strategy
        if ($mode === 'public') {
            unset($headers['Authorization']);
        } elseif ($mode === 'machine') {
            unset($headers['Authorization']);
            $aud = $cfg['token_service'] ?? $service;
            $headers['Authorization'] = ['Bearer '.$this->broker->forAudience($aud)];
        } // mode=user keeps incoming Authorization (route may be protected by verify.jwt)

        // Build request
        $opts = ['headers' => $headers, 'query' => $req->query()];
        if (! in_array($method, ['GET', 'DELETE'])) {
            $ct = $req->header('Content-Type', '');
            if (str_contains($ct, 'multipart/form-data')) {
                $multipart = [];
                foreach ($req->all() as $name => $value) {
                    if (is_array($value)) {
                        $value = json_encode($value);
                    }
                    $multipart[] = ['name' => $name, 'contents' => (string) $value];
                }
                foreach ($req->allFiles() as $name => $file) {
                    $multipart[] = [
                        'name' => $name,
                        'contents' => fopen($file->getRealPath(), 'r'),
                        'filename' => $file->getClientOriginalName(),
                    ];
                }
                $opts['multipart'] = $multipart;
                unset($opts['headers']['Content-Type']);
            } else {
                $opts['body'] = $req->getContent();
            }
        }

        // Retries on 5xx
        $retries = (int) config('gateway.cb.retries', 1);
        $delayMs = (int) config('gateway.cb.retry_delay', 150);

        attempt:
        $res = $client->request($method, $url, $opts);
        $status = $res->getStatusCode();

        if ($status >= 500) {
            $this->recordFailure($cbKey, (int) ($cfg['circuit_ttl'] ?? 30));
            if ($retries-- > 0) {
                // usleep($delayMs * 1000);
                // goto attempt;
            }
        } else {
            $this->recordSuccess($cbKey);
        }

        // log basic access line
        $lat = (int) ((microtime(true) - $start) * 1000);

        // Pass-through
        $body = (string) $res->getBody();
        $out = response($body, $status);
        foreach (['Content-Type', 'Cache-Control', 'ETag', 'Location'] as $h) {
            if ($res->hasHeader($h)) {
                $out->header($h, $res->getHeaderLine($h));
            }
        }

        return $out;
    }

    // ---- Circuit breaker helpers ----
    private function isOpen(string $key, int $ttl): bool
    {
        $state = Cache::get("$key:state", 'closed');
        if ($state === 'open') {
            $opened = (int) Cache::get("$key:opened_at", 0);
            $cool = (int) config('gateway.cb.cooldown', 30);
            if (time() - $opened > $cool) {
                Cache::put("$key:state", 'half', $ttl);

                return false;
            }

            return true;
        }

        return false;
    }

    private function recordFailure(string $key, int $ttl): void
    {
        $count = Cache::increment("$key:failures");
        Cache::put("$key:failures_ttl", 1, $ttl);
        if ($count >= (int) config('gateway.cb.threshold', 5)) {
            Cache::put("$key:state", 'open', $ttl);
            Cache::put("$key:opened_at", time(), $ttl);
            Cache::forget("$key:failures");
        }
    }

    private function recordSuccess(string $key): void
    {
        if (Cache::get("$key:state") === 'half') {
            Cache::put("$key:state", 'closed');
        }
        Cache::forget("$key:failures");
    }
}
