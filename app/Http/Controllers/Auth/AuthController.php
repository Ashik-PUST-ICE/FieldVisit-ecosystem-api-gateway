<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Redis;

class AuthController extends Controller
{
    public function logout(Request $request)
    {
        $sid = (string) $request->header('X-Session-Token', '');
        if ($sid === '') {
            return response()->json(['error' => 'Missing session token'], 422);
        }
        $key = "gw:tokens:{$sid}";
        $vault = json_decode(Redis::get($key) ?? '[]', true);
        $access  = $vault['access_token']  ?? null;
        if ($access) {
            try {
                $resp = Http::withToken($access)
                    ->acceptJson()
                    ->post(rtrim(env('AUTH_SERVICE_BASE_URI'), '/') . '/v1/logout');

                if ($resp->status() === 401 || $resp->ok()) {
                    Redis::del($key);
                    return response()->json(['status' => true]);
                }
                Log::warning('Auth-service logout response', ['status' => $resp->body(), 'ok' => $resp->ok()]);
            } catch (\Throwable $e) {
                Log::warning('Auth-service logout call failed', ['error' => $e->getMessage()]);
            }
        }
        return response()->json(['status' => false], 500);
    }

    public function refresh(Request $request)
    {
        $sid = (string) $request->header('X-Session-Token', '');
        info('Refresh called, session id: ' . $sid);
        if ($sid === '') {
            return response()->json(['error' => 'missing_session'], 422);
        }

        $key   = "gw:tokens:{$sid}";
        $vault = json_decode(Redis::get($key) ?? '[]', true);
        info('Current vault', $vault);
        $refresh = $vault['refresh_token'] ?? null;
        if (!$refresh) {
            Redis::del($key);
            return response()->json(['error' => 'no_refresh_token'], 401);
        }
        try {
            $response = Http::acceptJson()
                ->post(rtrim(env('AUTH_SERVICE_MAIN_URI'), '/') . '/auth/refresh', [
                    'refresh_token' => $refresh,
                ]);
            $token = $response->json();
            info('token', $token);
            $token = $token['data'] ?? [];
            $newVault = [
                'access_token'  => $token['access_token'] ?? null,
                'refresh_token' => $token['refresh_token'] ?? null,
                'token_type'    => $token['token_type'] ?? 'Bearer',
                'expires_at'    => now()->addSeconds($token['expires_in'] ?? 3600)->timestamp,
            ];
            info('refresh token', $newVault);
            Redis::setex($key, 60 * 60 * 24 * 15, json_encode($newVault));
            return response()->json([
                'ok'          => true,
                'expires_in'  => $token['expires_in'] ?? 3600,
                'expires_at'  => $newVault['expires_at'],
            ]);
        } catch (\Throwable $e) {
            Log::warning('Refresh call failed', ['err' => $e->getMessage()]);
            return response()->json(['error' => 'refresh_network_error'], 502);
        }
        return response()->json(['error' => 'refresh_failed'], 500);
    }
}
