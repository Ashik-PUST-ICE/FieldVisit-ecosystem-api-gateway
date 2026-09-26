<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;

Route::middleware(['attach.gateway.token', 'verify.jwt'])->post('/logout', [AuthController::class, 'logout']);
Route::middleware(['attach.gateway.token'])->post('/refresh', [AuthController::class, 'refresh']);
