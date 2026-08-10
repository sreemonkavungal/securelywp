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
    $options = get_option('securelywp_headers_options', []);
    
    if (!empty($options['referrer_policy_active']) && !empty($options['referrer_policy'])) {
        header('Referrer-Policy: ' . sanitize_text_field($options['referrer_policy']));
    }
}