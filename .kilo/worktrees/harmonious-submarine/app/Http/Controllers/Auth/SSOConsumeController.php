<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;

class SSOConsumeController extends Controller
{
    public function consume(Request $request)
    {
        $tid = (string) $request->query('tid', '');
        $return = (string) $request->query('return', 'http://localhost:5173/callback');
        abort_if($tid === '', 422, 'Missing ticket');

        $payload = ['ticket' => $tid];
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $hmac = hash_hmac('sha256', $body, env('SSO_SHARED_SECRET'));

        $resp = Http::withHeaders(['X-SSO-HMAC' => $hmac])
            ->acceptJson()
            ->post(rtrim(env('AUTH_SERVICE_MAIN_URI'), '/') . '/auth/ticket/redeem', $payload);

        if (! $resp->successful()) {
            return redirect()->away($this->append($return, ['error' => 'resolve_failed']));
        }

        $tok = $resp->json();
        $token = $tok['data'] ?? null;
        $sid = Str::uuid()->toString();
        Redis::setex("gw:tokens:{$sid}", 60 * 60 * 24 * 15, json_encode([
            'access_token' => $token['access_token'] ?? null,
            'refresh_token' => $token['refresh_token'] ?? null,
            'token_type' => $token['token_type'] ?? 'Bearer',
            'expires_at' => now()->addSeconds($token['expires_in'] ?? 3600)->timestamp,
        ]));

        return redirect()->away($return . '#sid=' . rawurlencode($sid));
    }

    private function append(string $url, array $q): string
    {
        $sep = str_contains($url, '?') ? '&' : '?';

        return $url . $sep . http_build_query($q);
    }
}
