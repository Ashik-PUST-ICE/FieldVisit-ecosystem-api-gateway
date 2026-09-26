<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Symfony\Component\HttpFoundation\Response;

class AttachGatewayToken
{
    public function handle(Request $request, Closure $next): Response
    {
        $incoming = (string) $request->headers->get('Authorization', '');
        if (!$incoming || !str_starts_with($incoming, 'Bearer ')) {
            $token = preg_replace('/^(?:\s*Bearer\s+)+/i', '', $incoming);
            if ($token !== '' && $token !== 'undefined') {
                $request->headers->set('Authorization', 'Bearer ' . $token);

                return $next($request);
            }
        }

        // Read opaque session token from header (cookie-less)
        $sid = (string) $request->headers->get('X-Session-Token', '');
        if ($sid === '') {
            return $next($request);
        }

        $raw = Redis::get("gw:tokens:{$sid}");
        if (! $raw) {
            return $next($request);
        }

        $vault = json_decode($raw, true) ?: [];
        $access = (string) ($vault['access_token'] ?? '');
        if ($access !== '') {
            $request->headers->set('Authorization', 'Bearer ' . $access);
        }

        return $next($request);
    }
}
