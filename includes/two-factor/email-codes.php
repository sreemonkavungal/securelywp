<?php
/**
 * SecurelyWP Email 2FA Handler
 *
 * Handles generation and verification of email-based 2FA codes.
 *
 * @package SecurelyWP
 * @since 1.0.7
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Generate and send email 2FA code.
 *
 * @param int $user_id User ID.
 * @return string Generated code.
 */
function securelywp_generate_email_code($user_id) {
    $code = wp_generate_password(6, false, false);
    set_transient('securelywp_email_2fa_code_' . $user_id, hash('sha256', $code), 15 * MINUTE_IN_SECONDS);

    $user = get_userdata($user_id);
    $subject = esc_html__('Your SecurelyWP 2FA Code', 'securelywp');
    $message = sprintf(
        esc_html__('Your two-factor authentication code is: %s. This code will expire in 15 minutes.', 'securelywp'),
        $code
    );
    wp_mail($user->user_email, $subject, $message);

    return $code;
}

/**
 * Verify email 2FA code.
 *
 * @param int $user_id User ID.
 * @param string $code Code to verify.
 * @return bool True if valid, false otherwise.
 */
function securelywp_verify_email_code($user_id, $code) {
    $stored_hash = get_transient('securelywp_email_2fa_code_' . $user_id);
    if ($stored_hash && hash('sha256', $code) === $stored_hash) {
        delete_transient('securelywp_email_2fa_code_' . $user_id);
        return true;
    }
    return false;
}