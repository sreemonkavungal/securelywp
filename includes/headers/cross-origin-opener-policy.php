<?php
/**
 * SecurelyWP Cross-Origin-Opener-Policy Header
 *
 * Adds the Cross-Origin-Opener-Policy header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.2.3
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('send_headers', 'securelywp_add_coop_header');

function securelywp_add_coop_header() {
    if (headers_sent()) {
        return;
    }

    $options = get_option('securelywp_headers_options', []);
    if (empty($options['coop_active'])) {
        return;
    }

    $policy = isset($options['coop']) ? sanitize_text_field($options['coop']) : 'same-origin';
    $allowed = ['same-origin', 'same-origin-allow-popups', 'unsafe-none'];
    if (!in_array($policy, $allowed, true)) {
        $policy = 'same-origin';
    }

    header('Cross-Origin-Opener-Policy: ' . $policy, true);
}
