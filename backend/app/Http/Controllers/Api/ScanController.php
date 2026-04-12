<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use Illuminate\Http\Request;

class ScanController extends Controller
{
    public function index()
    {
        $scans = Scan::orderBy('created_at', 'desc')->take(20)->get();
        return response()->json($scans);
    }

    public function show($id)
    {
        $scan = Scan::findOrFail($id);
        return response()->json($scan);
    }
}
