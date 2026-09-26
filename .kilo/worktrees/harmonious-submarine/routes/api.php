<?php

use App\Http\Controllers\Api\ProxyController;
use App\Http\Controllers\Auth\AuthController;
use Illuminate\Support\Facades\Route;

// Health
Route::get('/healthz', fn() => response()->json(['ok' => true]));

// Public passthrough (no auth) e.g. /api/p/billing_service/v1/plans
Route::match(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], '/p/{service}/{path?}', function ($service, $path = null) {
    return app(ProxyController::class)->forward(request(), $service, $path, 'public');
})->where('path', '.*');

// Authenticated user passthrough (validate at edge, then forward same token)
Route::middleware(['attach.gateway.token', 'verify.jwt'])->match(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], '/u/{service}/{path?}', function ($service, $path = null) {
    return app(ProxyController::class)->forward(request(), $service, $path, 'user');
})->where('path', '.*');

// Internal machine (client_credentials)
Route::match(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], '/m/{service}/{path?}', function ($service, $path = null) {
    return app(ProxyController::class)->forward(request(), $service, $path, 'machine');
})->where('path', '.*');

require __DIR__ . '/auth.php';
