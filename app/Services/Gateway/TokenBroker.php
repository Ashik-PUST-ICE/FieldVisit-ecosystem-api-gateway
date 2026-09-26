<?php

namespace App\Services\Gateway;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;

class TokenBroker
{
    public function __construct(private ?Client $http = null)
    {
        $this->http = $http ?: new Client(['timeout' => 3.0, 'http_errors' => false, 'verify' => true]);
    }

    public function forAudience(string $aud): string
    {
        $key = "gw.machine.token.$aud";

        return Cache::remember($key, now()->addMinutes(config('gateway.machine_token_ttl', 8)), function () use ($aud) {
            $res = $this->http->post(config('gateway.token_url'), [
                'form_params' => [
                    'grant_type' => 'client_credentials',
                    'client_id' => config('gateway.client_id'),
                    'client_secret' => config('gateway.client_secret'),
                    'audience' => $aud,            // downstream can verify aud
                    'scope' => 'gateway:proxy', // optional coarse scope
                ],
            ]);
            $json = json_decode((string) $res->getBody(), true);
            abort_unless(($json['access_token'] ?? null), 500, 'Unable to obtain machine token');

            return $json['access_token'];
        });
    }
}
