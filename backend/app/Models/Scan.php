<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Scan extends Model
{
    protected $fillable = [
        'network',
        'host',
        'type',
        'result'
    ];

    protected $casts = [
        'result' => 'array'
    ];
}
