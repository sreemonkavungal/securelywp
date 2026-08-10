<?php
/**
 * SecurelyWP TOTP Handler
 *
 * Handles generation and verification of TOTP codes for authenticator apps.
 *
 * @package SecurelyWP
 * @since 1.0.7
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Generate TOTP secret.
 *
 * @return string Base32-encoded secret.
 */
function securelywp_generate_totp_secret() {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 16; $i++) {
        $secret .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $secret;
}

/**
 * Generate TOTP URI for QR code.
 *
 * @param string $username Username for label.
 * @param string $secret TOTP secret.
 * @return string TOTP URI.
 */
function securelywp_generate_totp_uri($username, $secret) {
    $site_name = get_bloginfo('name');
    return sprintf(
        'otpauth://totp/%s:%s?secret=%s&issuer=%s',
        rawurlencode($site_name),
        rawurlencode($username),
        $secret,
        rawurlencode($site_name)
    );
}

/**
 * Verify TOTP code.
 *
 * @param string $secret TOTP secret.
 * @param string $code Code to verify.
 * @return bool True if valid, false otherwise.
 */
function securelywp_verify_totp_code($secret, $code) {
    $time_step = 30;
    $current_time = floor(time() / $time_step);
    $secret_bytes = securelywp_base32_decode($secret);

    for ($i = -1; $i <= 1; $i++) {
        $time = pack('NN', 0, $current_time + $i);
        $hash = hash_hmac('sha1', $time, $secret_bytes, true);
        $offset = ord($hash[19]) & 0x0F;
        $code_value = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % 1000000;
        $code_value = str_pad($code_value, 6, '0', STR_PAD_LEFT);
        if ($code_value === $code) {
            return true;
        }
    }
    return false;
}

/**
 * Decode base32 string.
 *
 * @param string $base32 Base32-encoded string.
 * @return string Decoded binary string.
 */
function securelywp_base32_decode($base32) {
    $base32 = strtoupper($base32);
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binary = '';
    for ($i = 0; $i < strlen($base32); $i++) {
        $value = strpos($chars, $base32[$i]);
        $binary .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    for ($i = 0; $i < strlen($binary); $i += 8) {
        $byte = substr($binary, $i, 8);
        $bytes .= chr(bindec($byte));
    }
    return $bytes;
}