<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT verification (used by VerifyJwt in the gateway)
    |--------------------------------------------------------------------------
    | Prefer JWKS when available; fall back to a PEM URL. Issuer checks are
    | flexible: only enforced if AUTH_REQUIRE_ISS=true and/or issuers provided.
    */
    'issuer' => env('AUTH_ISSUER', ''), // single issuer (optional)
    'issuers' => array_filter(array_map('trim', explode(',', env('AUTH_ISSUERS', '')))), // comma-separated list
    'require_iss' => (bool) env('AUTH_REQUIRE_ISS', false), // require 'iss' claim strictly?
    'audience' => env('AUTH_AUDIENCE', ''), // optional (set only if your tokens include aud)

    // Key sources (prefer JWKS)
    'jwks_url' => env('AUTH_JWKS_URL', null),              // e.g. https://auth-service.test/.well-known/jwks.json
    'public_pem' => env('AUTH_PUBLIC_PEM_URL', null),        // e.g. https://auth-service.test/api/v1/auth/public-key
    'jwks_ttl' => (int) env('AUTH_JWKS_TTL', 15),          // minutes cache for JWKS/PEM

    /*
    |--------------------------------------------------------------------------
    | Machine (client_credentials) token settings
    |--------------------------------------------------------------------------
    | Used by MachineTokenManager when the gateway (or other services) needs to
    | call downstream services without a user context.
    */
    'client_id' => env('GATEWAY_CLIENT_ID', 'gateway'),
    'client_secret' => env('GATEWAY_CLIENT_SECRET', ''),
    'token_url' => env('GATEWAY_TOKEN_URL', ''),       // e.g. https://auth-service.test/oauth/token
    'machine_token_ttl' => (int) env('MACHINE_TOKEN_TTL_MIN', 8), // minutes fallback if expires_in missing

    /*
    |--------------------------------------------------------------------------
    | Proxy / Resilience defaults
    |--------------------------------------------------------------------------
    */
    'cb' => [
        'window' => (int) env('GW_CB_WINDOW', 60),   // seconds to observe failures
        'threshold' => (int) env('GW_CB_THRESHOLD', 5), // failures before opening circuit
        'cooldown' => (int) env('GW_CB_COOLDOWN', 30), // seconds before half-open
        'timeout' => (float) env('GW_HTTP_TIMEOUT', 3.0), // per-request timeout (seconds)
        'retries' => (int) env('GW_HTTP_RETRIES', 1),     // retry count on 5xx
        'retry_delay' => (int) env('GW_HTTP_RETRY_DELAY', 150), // ms between retries
    ],

    /*
    |--------------------------------------------------------------------------
    | Security & headers
    |--------------------------------------------------------------------------
    */
    // Only these request headers are forwarded downstream
    'forward_headers' => [
        'accept',
        'authorization',
        'content-type',
        'x-request-id',
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-real-ip',
    ],

    // If true, disable TLS verification ONLY in local env (handy for self-signed dev certs)
    'allow_insecure_tls_local' => (bool) env('GW_ALLOW_INSECURE_TLS_LOCAL', true),

    // Name of the correlation header we set/propagate
    'request_id_header' => env('GW_REQUEST_ID_HEADER', 'X-Request-ID'),

    /*
    |--------------------------------------------------------------------------
    | Downstream services registry
    |--------------------------------------------------------------------------
    | - base_uri:      full base URL for the service’s API
    | - cache_ttl:     optional response cache (seconds) if you implement caching layer
    | - circuit_ttl:   circuit breaker memory TTL (seconds)
    | - token_service: audience/friendly name to request in machine tokens
    */
    'services' => [
        'whatsapp_service' => [
            'base_uri' => env('WHATSAPP_SERVICE_BASE_URI', 'http://103.107.160.22:3001'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'whatsapp-service',
        ],
        'auth_service' => [
            'base_uri' => env('AUTH_SERVICE_BASE_URI', 'https://saltsync-ecosystem-auth.test/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'auth-service',
        ],

        'notification_service' => [
            'base_uri' => env('NOTIFICATION_SERVICE_BASE_URI', 'http://103.107.160.22:8002/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'notification-service',
        ],

        'log_service' => [
            'base_uri' => env('LOG_SERVICE_BASE_URI', 'http://103.107.160.22:8005/api'),
            'cache_ttl' => 600,
            'circuit_ttl' => 30,
            'token_service' => 'log-service',
        ],

        'saltsync_service' => [
            'base_uri' => env('SALTSYNC_SERVICE_BASE_URI', 'https://care.saltsync.com/api'),
            'cache_ttl' => 600,
            'circuit_ttl' => 30,
            'token_service' => 'saltsync-service',
        ],

        'support_service' => [
            'base_uri' => env('SUPPORT_SERVICE_BASE_URI', 'http://103.107.160.22:8006/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'support-service',
        ],
        'business_service' => [
            'base_uri' => env('BUSINESS_SERVICE_BASE_URI', 'https://saltsync-ecosystem-business.test/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'business_service',
        ],
        'network_service' => [
            'base_uri' => env('NETWORK_SERVICE_BASE_URI', 'http://103.107.160.22:8008/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'network-service',
        ],

        'billing_service' => [
            'base_uri' => env('BILLING_SERVICE_BASE_URI', 'http://103.107.160.22:8008/api'),
            'cache_ttl' => 300,
            'circuit_ttl' => 20,
            'token_service' => 'billing-service',
        ],
    ],
];
