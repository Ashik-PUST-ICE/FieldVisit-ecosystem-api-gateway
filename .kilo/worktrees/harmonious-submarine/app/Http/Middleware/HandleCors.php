<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class HandleCors
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return response('', 204)
                ->header('Access-Control-Allow-Origin', $request->headers->get('Origin') ?? '*')
                ->header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
                ->header('Access-Control-Allow-Headers', 'Authorization,Content-Type,X-Request-ID')
                ->header('Access-Control-Max-Age', '600');
        }
        $res = $next($request);

        return $res
            ->header('Access-Control-Allow-Origin', $request->headers->get('Origin') ?? '*')
            ->header('Vary', 'Origin')
            ->header('Access-Control-Expose-Headers', 'X-Request-ID');
    }
}
