<?php
/**
 * SecurelyWP Recovery Codes Handler
 *
 * @package SecurelyWP
 * @since 1.0.7
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Generate recovery codes for a user.
 *
 * @return array{plain: string[], hashed: string[]}
 */
function securelywp_generate_recovery_codes() {
    $plain = [];
    $hashed = [];

    for ($i = 0; $i < 8; $i++) {
        $code = wp_generate_password(12, false, false);
        $plain[] = $code;
        $hashed[] = wp_hash_password($code);
    }

    return [
        'plain'  => $plain,
        'hashed' => $hashed,
    ];
}

/**
 * Store plain recovery codes for one-time display.
 *
 * @param int   $user_id User ID.
 * @param array $plain_codes Plain recovery codes.
 * @return void
 */
function securelywp_store_recovery_codes_for_display($user_id, $plain_codes) {
    set_transient(
        'securelywp_recovery_codes_display_' . absint($user_id),
        $plain_codes,
        15 * MINUTE_IN_SECONDS
    );
}

/**
 * Get recovery codes available for one-time display.
 *
 * @param int $user_id User ID.
 * @return array
 */
function securelywp_get_recovery_codes_for_display($user_id) {
    $codes = get_transient('securelywp_recovery_codes_display_' . absint($user_id));
    return is_array($codes) ? $codes : [];
}

/**
 * Verify a recovery code.
 *
 * @param int    $user_id User ID.
 * @param string $code Code to verify.
 * @return bool
 */
function securelywp_verify_recovery_code($user_id, $code) {
    $user_2fa_options = get_user_meta($user_id, 'securelywp_2fa_user_options', true) ?: [];
    $recovery_codes = !empty($user_2fa_options['recovery_codes']) ? $user_2fa_options['recovery_codes'] : [];

    foreach ($recovery_codes as $index => $stored_code) {
        $valid = false;

        if (is_string($stored_code) && strpos($stored_code, '$') === 0) {
            $valid = wp_check_password($code, $stored_code);
        } elseif ($stored_code === $code) {
            $valid = true;
        }

        if ($valid) {
            unset($recovery_codes[$index]);
            $user_2fa_options['recovery_codes'] = array_values($recovery_codes);
            update_user_meta($user_id, 'securelywp_2fa_user_options', $user_2fa_options);
            return true;
        }
    }

    return false;
}
