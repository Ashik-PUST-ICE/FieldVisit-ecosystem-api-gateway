<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class CorrelationId
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $id = $request->header('X-Request-ID') ?: Str::uuid()->toString();
        $request->headers->set('X-Request-ID', $id);
        $res = $next($request);
        $res->headers->set('X-Request-ID', $id);

        return $res;
    }
}
