<?php
/**
 * SecurelyWP X-Frame-Options Header
 *
 * Adds the X-Frame-Options header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_x_frame_options_header');

function securelywp_add_x_frame_options_header() {
    $options = get_option('securelywp_headers_options', []);
    
    if (!empty($options['x_frame_options_active']) && !empty($options['x_frame_options'])) {
        $x_frame_options = strtoupper(sanitize_text_field($options['x_frame_options']));
        if ($x_frame_options === 'ALLOW-FROM' && !empty($options['x_frame_options_allow_from_url'])) {
            $x_frame_options .= ' ' . esc_url_raw($options['x_frame_options_allow_from_url']);
        }
        header('X-Frame-Options: ' . $x_frame_options);
    }
}