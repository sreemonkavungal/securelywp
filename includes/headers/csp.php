<?php
/**
 * SecurelyWP Content Security Policy Header
 *
 * Adds the Content Security Policy header based on user settings.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

add_action('send_headers', 'securelywp_add_csp_header');

function securelywp_add_csp_header() {
    $options = get_option('securelywp_headers_options', []);
    
    if (!empty($options['csp_active']) && !empty($options['csp'])) {
        $csp = sanitize_text_field($options['csp']);
        if (!empty($options['csp_report_uri'])) {
            $csp .= ' report-uri ' . esc_url_raw($options['csp_report_uri']);
        }
        header('Content-Security-Policy: ' . $csp);
    }
}