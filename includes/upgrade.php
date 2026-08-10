<?php
/**
 * SecurelyWP upgrade routines.
 *
 * @package SecurelyWP
 * @since 1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Run plugin upgrades when the stored version is behind.
 *
 * @return void
 */
function securelywp_maybe_upgrade() {
    $installed = get_option('securelywp_db_version', '0');

    if (version_compare($installed, SECURELYWP_VERSION, '>=')) {
        return;
    }

    if (version_compare($installed, '1.1.0', '<')) {
        securelywp_upgrade_to_110();
    }

    if (version_compare($installed, '1.2.0', '<')) {
        securelywp_upgrade_to_120();
    }

    if (version_compare($installed, '1.2.1', '<')) {
        securelywp_upgrade_to_121();
    }

    update_option('securelywp_db_version', SECURELYWP_VERSION, false);
}

/**
 * Ensure hardening options include new default values.
 *
 * @return void
 */
function securelywp_ensure_hardening_defaults() {
    $default_hardening_options = [
        'hide_wp_version' => true,
        'disable_php_uploads' => true,
        'prevent_user_enum' => true,
        'detect_admin_username' => true,
        'disable_file_edit' => true,
        'force_https' => true,
        'disable_xmlrpc' => true,
        'restrict_rest_api' => true,
        'disable_emojis' => true,
        'disable_embeds' => true,
        'brute_force_protection' => true,
    ];

    $stored_options = get_option('securelywp_hardening_options');
    if ($stored_options === false) {
        update_option('securelywp_hardening_options', $default_hardening_options);
        return;
    }

    $normalized = wp_parse_args((array) $stored_options, $default_hardening_options);
    if ($normalized !== $stored_options) {
        update_option('securelywp_hardening_options', $normalized);
    }
}

/**
 * Upgrade tasks for version 1.1.0.
 *
 * @return void
 */
function securelywp_upgrade_to_110() {
    $users = get_users(['fields' => 'ID']);

    foreach ($users as $user_id) {
        $options = get_user_meta($user_id, 'securelywp_2fa_user_options', true);
        if (!is_array($options) || empty($options['recovery_codes']) || !is_array($options['recovery_codes'])) {
            continue;
        }

        $needs_hash = false;
        foreach ($options['recovery_codes'] as $code) {
            if (is_string($code) && strpos($code, '$') !== 0) {
                $needs_hash = true;
                break;
            }
        }

        if (!$needs_hash) {
            continue;
        }

        $options['recovery_codes'] = array_map('wp_hash_password', $options['recovery_codes']);
        update_user_meta($user_id, 'securelywp_2fa_user_options', $options);
    }

    if (get_option('securelywp_vulnerability_options') === false) {
        update_option(
            'securelywp_vulnerability_options',
            [
                'auto_scan_enabled' => false,
                'auto_disable'      => false,
                'scan_frequency'    => 'weekly',
                'notify_email'      => sanitize_email(get_option('admin_email')),
            ]
        );
    }

    if (class_exists('SecurelyWP_Vulnerability_Scanner')) {
        $scanner = new SecurelyWP_Vulnerability_Scanner();
        $scanner->schedule_scan();
    }
}

/**
 * Upgrade tasks for version 1.2.0.
 *
 * @return void
 */
function securelywp_upgrade_to_120() {
    $default_hardening_options = [
        'hide_wp_version'         => true,
        'disable_php_uploads'     => true,
        'prevent_user_enum'       => true,
        'detect_admin_username'   => true,
        'disable_file_edit'       => true,
        'force_https'             => true,
        'disable_xmlrpc'          => true,
        'restrict_rest_api'       => true,
        'disable_emojis'          => true,
        'disable_embeds'          => true,
        'brute_force_protection'  => true,
    ];

    $default_headers_options = [
        'csp_active'                       => true,
        'csp'                              => 'upgrade-insecure-requests;',
        'csp_report_uri'                   => '',
        'hsts_active'                      => true,
        'hsts_max_age'                     => 31536000,
        'hsts_include_subdomains'          => true,
        'hsts_preload'                     => true,
        'x_frame_options_active'           => true,
        'x_frame_options'                  => 'SAMEORIGIN',
        'x_frame_options_allow_from_url'   => '',
        'referrer_policy_active'           => true,
        'referrer_policy'                  => 'strict-origin-when-cross-origin',
        'permissions_policy_active'        => true,
        'permissions_policy'               => 'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(self), encrypted-media=(), fullscreen=*, geolocation=(self), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=*, picture-in-picture=*, publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=*, usb=(), xr-spatial-tracking=*, gamepad=(), serial=()',
        'x_content_type_options_active'    => true,
        'x_content_type_options'           => true,
    ];

    $default_2fa_options = [
        'enforce_2fa_network' => false,
    ];

    $default_firewall_options = [
        'enable_firewall'   => true,
        'custom_rules'      => '',
        'whitelist'         => '',
        'check_request_uri' => true,
        'check_query_string' => true,
        'check_user_agent'  => true,
        'check_referrer'    => true,
        'check_post_body'   => true,
        'check_long_requests' => true,
    ];

    $default_vulnerability_options = [
        'auto_scan_enabled' => false,
        'auto_disable'      => false,
        'scan_frequency'    => 'weekly',
        'notify_email'      => sanitize_email(get_option('admin_email')),
    ];

    if (get_option('securelywp_options') === false) {
        update_option('securelywp_options', []);
    }

    if (get_option('securelywp_hardening_options') === false) {
        update_option('securelywp_hardening_options', $default_hardening_options);
    } else {
        update_option('securelywp_hardening_options', wp_parse_args((array) get_option('securelywp_hardening_options', []), $default_hardening_options));
    }

    if (get_option('securelywp_headers_options') === false) {
        update_option('securelywp_headers_options', $default_headers_options);
    } else {
        update_option('securelywp_headers_options', wp_parse_args((array) get_option('securelywp_headers_options', []), $default_headers_options));
    }

    if (get_option('securelywp_2fa_options') === false) {
        update_option('securelywp_2fa_options', $default_2fa_options);
    } else {
        update_option('securelywp_2fa_options', wp_parse_args((array) get_option('securelywp_2fa_options', []), $default_2fa_options));
    }

    if (get_option('securelywp_firewall_options') === false) {
        update_option('securelywp_firewall_options', $default_firewall_options);
    } else {
        update_option('securelywp_firewall_options', wp_parse_args((array) get_option('securelywp_firewall_options', []), $default_firewall_options));
    }

    if (get_option('securelywp_vulnerability_options') === false) {
        update_option('securelywp_vulnerability_options', $default_vulnerability_options);
    } else {
        update_option('securelywp_vulnerability_options', wp_parse_args((array) get_option('securelywp_vulnerability_options', []), $default_vulnerability_options));
    }

    if (class_exists('SecurelyWP_Vulnerability_Scanner')) {
        $scanner = new SecurelyWP_Vulnerability_Scanner();
        $scanner->schedule_scan();
    }
}

/**
 * Upgrade tasks for version 1.2.1.
 *
 * @return void
 */
function securelywp_upgrade_to_121() {
    $default_hardening_options = [
        'hide_wp_version'         => true,
        'disable_php_uploads'     => true,
        'prevent_user_enum'       => true,
        'detect_admin_username'   => true,
        'disable_file_edit'       => true,
        'force_https'             => true,
        'disable_xmlrpc'          => true,
        'restrict_rest_api'       => true,
        'disable_emojis'          => true,
        'disable_embeds'          => true,
        'brute_force_protection'  => true,
    ];

    if (get_option('securelywp_hardening_options') === false) {
        update_option('securelywp_hardening_options', $default_hardening_options);
    } else {
        update_option('securelywp_hardening_options', wp_parse_args((array) get_option('securelywp_hardening_options', []), $default_hardening_options));
    }
}
