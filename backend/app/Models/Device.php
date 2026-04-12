<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Device extends Model
{
    protected $fillable = [
        'ip',
        'hostname',
        'state',
        'open_ports',
        'is_new',
        'first_seen',
        'last_seen'
    ];

    protected $casts = [
        'open_ports' => 'array',
        'is_new'     => 'boolean',
        'first_seen' => 'datetime',
        'last_seen'  => 'datetime'
    ];
}
