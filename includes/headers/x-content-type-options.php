<?php
/**
 * SecurelyWP X-Content-Type-Options Header
 *
 * Adds the X-Content-Type-Options header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_x_content_type_options_header');

function securelywp_add_x_content_type_options_header() {
    $options = get_option('securelywp_headers_options', []);
    
    if (!empty($options['x_content_type_options_active']) && !empty($options['x_content_type_options'])) {
        header('X-Content-Type-Options: nosniff');
    }
}