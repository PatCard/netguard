<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ChatHistory extends Model
{
    protected $table = 'chat_history';

    protected $fillable = [
        'role',
        'content'
    ];
}
