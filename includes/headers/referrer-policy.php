<?php
/**
 * SecurelyWP Referrer Policy Header
 *
 * Adds the Referrer-Policy header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_referrer_policy_header');

function securelywp_add_referrer_policy_header() {
    if (headers_sent()) {
        return;
    }

    $options = get_option('securelywp_headers_options', []);
    if (empty($options['referrer_policy_active']) || empty($options['referrer_policy'])) {
        return;
    }

    $policy = sanitize_text_field($options['referrer_policy']);
    $allowed = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];
    if (!in_array($policy, $allowed, true)) {
        $policy = 'strict-origin-when-cross-origin';
    }

    header('Referrer-Policy: ' . $policy, true);
}