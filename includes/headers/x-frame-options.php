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
    if (headers_sent()) {
        return;
    }

    $options = get_option('securelywp_headers_options', []);
    if (empty($options['x_frame_options_active']) || empty($options['x_frame_options'])) {
        return;
    }

    $x_frame_options = strtoupper(sanitize_text_field($options['x_frame_options']));
    if (!in_array($x_frame_options, ['DENY', 'SAMEORIGIN', 'ALLOW-FROM'], true)) {
        $x_frame_options = 'SAMEORIGIN';
    }

    if ($x_frame_options === 'ALLOW-FROM' && !empty($options['x_frame_options_allow_from_url'])) {
        $allow_from = esc_url_raw($options['x_frame_options_allow_from_url']);
        if ($allow_from) {
            $x_frame_options .= ' ' . $allow_from;
        } else {
            $x_frame_options = 'SAMEORIGIN';
        }
    }

    header('X-Frame-Options: ' . $x_frame_options, true);
}