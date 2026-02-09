<?php
namespace Hillzacky\Dana;

class Dana {

// Helper: Format timestamp ISO8601 dengan offset +07:00 (sesuaikan zona waktu jika perlu)
static function timestamp(string $timezone = 'Asia/Jakarta'): string {
    $dt = new DateTime('now', new DateTimeZone($timezone));
    // Format: 2022-11-30T09:45:35+07:00
    return $dt->format('Y-m-d\TH:i:sP');
}

static function minifyJson(string $json): string {
    $decoded = json_decode($json, true);
    if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
        // Jika bukan JSON valid, kembalikan apa adanya
        return $json;
    }
    return json_encode($decoded, JSON_UNESCAPED_SLASHES);
}

// Helper: Sign string dengan RSA2048-SHA256, hasil Base64
static function rsaSha256SignBase64(string $data, string $privateKeyPem): string {
    $pkey = openssl_pkey_get_private($privateKeyPem);
    if (!$pkey) {
        throw new RuntimeException('Private key invalid atau tidak dapat dibaca.');
    }
    $signature = '';
    $ok = openssl_sign($data, $signature, $pkey, OPENSSL_ALGO_SHA256);
    openssl_free_key($pkey);

    if (!$ok) {
        throw new RuntimeException('Gagal melakukan openssl_sign.');
    }
    return base64_encode($signature);
}

// 1) Build signature untuk Apply Token:
// signing_string = X-CLIENT-KEY + "|" + X-TIMESTAMP
static function applyToken(string $clientKey, string $timestamp, string $privateKeyPem): string {
    $signingString = $clientKey . '|' . $timestamp;
    return self::rsaSha256SignBase64($signingString, $privateKeyPem);
}

// 2) Build signature untuk API Transaksional:
// signing_string = METHOD + ":" + RELATIVE_PATH + ":" + lower_hex(sha256(minify(body))) + ":" + X-TIMESTAMP
static function transactional(string $method, string $relativePath, string $bodyJson, string $timestamp, string $privateKeyPem): string {
    $minifiedBody = self::minifyJson($bodyJson);
    $bodyHashHex = hash('sha256', $minifiedBody);
    $signingString = strtoupper($method) . ':' . $relativePath . ':' . $bodyHashHex . ':' . $timestamp;
    return self::rsaSha256SignBase64($signingString, $privateKeyPem);
}

// Contoh PEM private key (sandbox/production). Pastikan sesuai format PEM.
static $privateKeyPem = <<<PEM
-----BEGIN PRIVATE KEY-----
...isi private key Anda...
-----END PRIVATE KEY-----
PEM;

// Contoh 1: Apply Token request (jika Anda sedang memanggil API yang butuh signature versi Apply Token)
$clientKey  = 'ISI_X_CLIENT_KEY_ANDA';
$timestamp  = self::timestamp(); // contoh: 2022-11-30T09:45:35+07:00
$xSignature = self::applyToken($clientKey, $timestamp, $privateKeyPem);

// Siapkan request Apply Token (URL contoh; sesuaikan dengan endpoint Apply Token Anda)
$applyTokenUrl = 'https://api-sandbox.dana.id/.../apply-token';
$applyTokenBody = json_encode([
    // isi payload sesuai spesifikasi Apply Token Anda
], JSON_UNESCAPED_SLASHES);

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $applyTokenUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CUSTOMREQUEST  => 'POST',
    CURLOPT_POSTFIELDS     => $applyTokenBody,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'Accept: application/json',
        'X-CLIENT-KEY: ' . $clientKey,
        'X-TIMESTAMP: ' . $timestamp,
        'X-SIGNATURE: ' . $xSignature,
    ],
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);
$applyTokenResp = curl_exec($ch);
$applyTokenErr  = curl_error($ch);
$applyTokenCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Debug respons
// var_dump($applyTokenCode, $applyTokenResp, $applyTokenErr);

// Contoh 2: Transaksional (misal contoh dari dokumentasi: /v1.0/balance-inquiry.htm)
$baseUrl       = 'https://api-sandbox.dana.id'; // ganti sesuai sandbox/production Anda
$relativePath  = '/v1.0/balance-inquiry.htm';   // RELATIVE PATH sesuai dokumentasi
$method        = 'POST';

// Body contoh dari dokumentasi Authentication (silakan sesuaikan field aktual Anda)
$bodyArray = [
    "partnerReferenceNo" => "2020102900000000000001",
    "balanceTypes"       => ["BALANCE"],
    "additionalInfo"     => [
        "accessToken" => "fa8sjjEj813Y9JGoqwOeOPWbnt4CUpvIJbU1mMU4a11MNDZ7Sg5u9a"
    ]
];
$bodyJson = json_encode($bodyArray, JSON_UNESCAPED_SLASHES);

// Timestamp dan signature transaksional
$timestampTxn = self::timestamp();
$xSignatureTxn = self::transactional($method, $relativePath, $bodyJson, $timestampTxn, $privateKeyPem);

// Panggil API transaksional
$url = $baseUrl . $relativePath;

$ch2 = curl_init();
curl_setopt_array($ch2, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CUSTOMREQUEST  => $method,
    CURLOPT_POSTFIELDS     => $bodyJson,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'Accept: application/json',
        // Perhatikan: gunakan header yang diwajibkan oleh endpoint Anda.
        // Dari dokumentasi Authentication, minimal X-CLIENT-KEY, X-TIMESTAMP, X-SIGNATURE
        'X-CLIENT-KEY: ' . $clientKey,
        'X-TIMESTAMP: ' . $timestampTxn,
        'X-SIGNATURE: ' . $xSignatureTxn,
    ],
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);
$txnResp = curl_exec($ch2);
$txnErr  = curl_error($ch2);
$txnCode = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
curl_close($ch2);

// Debug respons
// var_dump($txnCode, $txnResp, $txnErr);

}