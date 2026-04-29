<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RunNetworkAudit implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public $timeout = 600;
    public string $jobId;
    public string $network;

    public function __construct(string $jobId, string $network)
    {
        $this->jobId = $jobId;
        $this->network = $network;
    }

    public function handle(): void
    {
        Log::info("RunNetworkAudit: starting {$this->jobId}");
        Cache::put("audit:{$this->jobId}:status", "running", 3600);

        try {
            $response = Http::timeout(500)->post('http://netguard_agent:5000/audit', [
                'network' => $this->network
            ]);

            if ($response->successful()) {
                Cache::put("audit:{$this->jobId}:result", $response->json(), 3600);
                Cache::put("audit:{$this->jobId}:status", "completed", 3600);
                Log::info("RunNetworkAudit: completed {$this->jobId}");
            } else {
                Cache::put("audit:{$this->jobId}:status", "failed", 3600);
                Cache::put("audit:{$this->jobId}:error", $response->body(), 3600);
                Log::error("RunNetworkAudit: failed {$this->jobId}: " . $response->body());
            }

        } catch (\Exception $e) {
            Log::error("RunNetworkAudit: exception {$this->jobId}: " . $e->getMessage());
            Cache::put("audit:{$this->jobId}:status", "failed", 3600);
            Cache::put("audit:{$this->jobId}:error", $e->getMessage(), 3600);
        }
    }
}
