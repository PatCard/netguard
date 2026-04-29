<?php

use App\Http\Controllers\Api\ChatController;
use App\Http\Controllers\Api\ScanController;
use App\Http\Controllers\Api\DeviceController;
use App\Jobs\RunNetworkAudit;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

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

// Audit asíncrono
Route::post('/audit', function (\Illuminate\Http\Request $request) {
    $request->validate(['network' => 'required|string']);
    $jobId = Str::uuid()->toString();
    Cache::put("audit:{$jobId}:status", "pending", 3600);
    RunNetworkAudit::dispatch($jobId, $request->network);
    return response()->json(['job_id' => $jobId, 'status' => 'pending']);
});

Route::get('/audit/{jobId}', function (string $jobId) {
    $status = Cache::get("audit:{$jobId}:status", "not_found");

    if ($status === "completed") {
        $result = Cache::get("audit:{$jobId}:result");
        return response()->json(['status' => 'completed', 'result' => $result]);
    }

    if ($status === "failed") {
        $error = Cache::get("audit:{$jobId}:error");
        return response()->json(['status' => 'failed', 'error' => $error]);
    }

    return response()->json(['status' => $status]);
});

Route::post('/report/pdf', function (\Illuminate\Http\Request $request) {
    $response = \Illuminate\Support\Facades\Http::timeout(60)->post('http://netguard_agent:5000/report/pdf', $request->all());
    return response($response->body(), 200, [
        'Content-Type' => 'application/pdf',
        'Content-Disposition' => 'attachment; filename="netguard-report.pdf"'
    ]);
});
