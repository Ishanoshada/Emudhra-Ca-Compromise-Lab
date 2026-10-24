<?php
// Test PHP's two HTTPS paths against the forged emSign chain.
// VULNERABLE = request succeeded against the forged cert.
// PROTECTED  = request failed with verify/revocation error.

$HOST = 'test.example.com';
$IP   = '127.0.0.1';
$PORT = 8443;
$OLD  = __DIR__ . DIRECTORY_SEPARATOR . 'old-cacert.pem';

function hdr() { echo str_repeat('=', 66) . "\n"; }

hdr();
echo " PHP " . PHP_VERSION . "  (" . PHP_OS_FAMILY . ")\n";
echo " curl extension:    " . (extension_loaded('curl')    ? 'yes' : 'no') . "\n";
echo " openssl extension: " . (extension_loaded('openssl') ? 'yes' : 'no') . "\n";
echo " openssl.cafile:    " . (ini_get('openssl.cafile') ?: '(not set)') . "\n";
echo " curl.cainfo:       " . (ini_get('curl.cainfo')    ?: '(not set)') . "\n";
hdr();
echo "\n";

// ---- Test 1: curl extension (uses Schannel on Windows) ----
if (extension_loaded('curl')) {
    foreach ([
        ['curl',            []],
        ['curl+no-revoke',  [CURLOPT_SSL_OPTIONS => defined('CURLSSLOPT_NO_REVOKE') ? CURLSSLOPT_NO_REVOKE : 0]],
    ] as [$label, $extra]) {
        $ch = curl_init();
        $base = [
            CURLOPT_URL            => "https://$HOST:$PORT/",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HEADER         => false,
            // force DNS to 127.0.0.1 without touching hosts file:
            CURLOPT_RESOLVE        => ["$HOST:$PORT:$IP"],
        ];
        curl_setopt_array($ch, $base + $extra);
        $body = curl_exec($ch);
        if ($body === false) {
            $errno = curl_errno($ch);
            $err   = curl_error($ch);
            echo "  [$label] PROTECTED — errno $errno: $err\n";
        } else {
            echo "  [$label] VULNERABLE — response: " . trim(substr($body, 0, 120)) . "\n";
        }
        curl_close($ch);
    }
    echo "\n";
}

// ---- Test 2: openssl stream with old-cacert.pem ----
if (extension_loaded('openssl')) {
    if (!file_exists($OLD)) {
        echo "  [openssl+old-cacert] SKIPPED — $OLD not found\n\n";
    } else {
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
                'peer_name'        => $HOST,
                'cafile'           => $OLD,
                'SNI_enabled'      => true,
            ],
        ]);
        $fp = @stream_socket_client(
            "ssl://$IP:$PORT",
            $errno, $errstr, 5,
            STREAM_CLIENT_CONNECT, $ctx
        );
        if ($fp === false) {
            echo "  [openssl+old-cacert] PROTECTED — $errno: $errstr\n";
        } else {
            echo "  [openssl+old-cacert] VULNERABLE — handshake OK\n";
            fclose($fp);
        }
        echo "\n";
    }

    // ---- Test 3: openssl with no cafile (uses whatever PHP has configured) ----
    $ctx = stream_context_create([
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
            'peer_name'        => $HOST,
            'SNI_enabled'      => true,
        ],
    ]);
    $fp = @stream_socket_client(
        "ssl://$IP:$PORT",
        $errno, $errstr, 5,
        STREAM_CLIENT_CONNECT, $ctx
    );
    if ($fp === false) {
        echo "  [openssl default] PROTECTED — $errno: $errstr\n";
    } else {
        echo "  [openssl default] VULNERABLE — handshake OK\n";
        fclose($fp);
    }
    echo "\n";
}

hdr();
echo " Notes:\n";
echo "   'curl' PROTECTED here is Windows Schannel, not PHP — Windows\n";
echo "   enforces the disallowed CTL regardless of PHP's CA settings.\n";
echo "   'openssl+old-cacert' VULNERABLE means old-cacert.pem (certifi\n";
echo "   2026.06.17) still carries emSign ECC Root CA - G3.\n";
hdr();