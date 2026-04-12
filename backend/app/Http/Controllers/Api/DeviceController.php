<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Device;

class DeviceController extends Controller
{
    public function index()
    {
        $devices = Device::orderBy('last_seen', 'desc')->get();
        return response()->json($devices);
    }

    public function show($id)
    {
        $device = Device::findOrFail($id);
        return response()->json($device);
    }
}
