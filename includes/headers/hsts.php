<?php
/**
 * SecurelyWP HTTP Strict Transport Security Header
 *
 * Adds the Strict-Transport-Security header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_hsts_header');

function securelywp_add_hsts_header() {
    $options = get_option('securelywp_headers_options', []);
    
    if (!empty($options['hsts_active']) && !empty($options['hsts_max_age']) && is_ssl()) {
        $hsts = 'max-age=' . absint($options['hsts_max_age']);
        if (!empty($options['hsts_include_subdomains'])) {
            $hsts .= '; includeSubDomains';
        }
        if (!empty($options['hsts_preload'])) {
            $hsts .= '; preload';
        }
        header('Strict-Transport-Security: ' . $hsts);
    }
}