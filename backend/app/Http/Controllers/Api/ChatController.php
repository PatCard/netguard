<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ChatHistory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class ChatController extends Controller
{
    public function send(Request $request)
    {
        $request->validate(['message' => 'required|string']);

        $history = ChatHistory::orderBy('created_at', 'desc')
            ->take(10)
            ->get()
            ->reverse()
            ->map(fn($h) => ['role' => $h->role, 'content' => $h->content])
            ->values()
            ->toArray();

        $response = Http::timeout(120)->post('http://netguard_agent:5000/chat', [
            'message' => $request->message,
            'history' => $history
        ]);

        if ($response->failed()) {
            return response()->json(['error' => 'Error al conectar con el agente'], 500);
        }

        $data = $response->json();

        ChatHistory::create(['role' => 'user',      'content' => $request->message]);
        ChatHistory::create(['role' => 'assistant', 'content' => $data['response']]);

        return response()->json(['response' => $data['response']]);
    }

    public function history()
    {
        $history = ChatHistory::orderBy('created_at', 'asc')->get();
        return response()->json($history);
    }

    public function clear()
    {
        ChatHistory::truncate();
        return response()->json(['message' => 'Historial eliminado']);
    }
}
