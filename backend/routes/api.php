<?php

use App\Http\Controllers\Api\ChatController;
use App\Http\Controllers\Api\ScanController;
use App\Http\Controllers\Api\DeviceController;
use Illuminate\Support\Facades\Route;

Route::prefix('chat')->group(function () {
    Route::post('/send',    [ChatController::class, 'send']);
    Route::get('/history',  [ChatController::class, 'history']);
    Route::delete('/clear', [ChatController::class, 'clear']);
});

Route::prefix('scans')->group(function () {
    Route::get('/',     [ScanController::class, 'index']);
    Route::get('/{id}', [ScanController::class, 'show']);
});

Route::prefix('devices')->group(function () {
    Route::get('/',     [DeviceController::class, 'index']);
    Route::get('/{id}', [DeviceController::class, 'show']);
});

Route::post('/audit', function (\Illuminate\Http\Request $request) {
    $request->validate(['network' => 'required|string']);
    $response = \Illuminate\Support\Facades\Http::timeout(300)->post('http://netguard_agent:5000/audit', [
        'network' => $request->network
    ]);
    return response()->json($response->json());
});
