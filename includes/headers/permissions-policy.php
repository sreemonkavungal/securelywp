<?php
/**
 * SecurelyWP Permissions Policy Header
 *
 * Adds the Permissions-Policy header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_permissions_policy_header');

function securelywp_add_permissions_policy_header() {
    if (headers_sent()) {
        return;
    }

    $options = get_option('securelywp_headers_options', []);
    if (empty($options['permissions_policy_active']) || empty($options['permissions_policy'])) {
        return;
    }

    $policy = trim(sanitize_text_field($options['permissions_policy']));
    if (empty($policy)) {
        return;
    }

    header('Permissions-Policy: ' . $policy, true);
}