<?php

use App\Http\Controllers\Auth\SSOConsumeController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/auth/sso/consume', [SSOConsumeController::class, 'consume']);
