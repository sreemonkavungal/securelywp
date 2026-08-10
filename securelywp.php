<?php
/**
 * Plugin Name: SecurelyWP – all-in-one security
 * Description: WordPress security with vulnerability scanning, hardening, headers, CAPTCHA, firewall, and two-factor authentication.
 * Version: 1.2.1
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: <a href="https://github.com/sreemonkavungal">SREEMON K S</a> | <a href="https://securelywp.com">SecurelyWP</a>
 * License: GPL-3.0
 * Text Domain: securelywp
 */

if (!defined('ABSPATH')) {
    exit;
}

define('SECURELYWP_VERSION', '1.2.1');
define('SECURELYWP_PATH', plugin_dir_path(__FILE__));
define('SECURELYWP_URL', plugin_dir_url(__FILE__));

require_once SECURELYWP_PATH . 'includes/helpers.php';
require_once SECURELYWP_PATH . 'includes/upgrade.php';
require_once SECURELYWP_PATH . 'includes/vulnerability-scanner.php';
require_once SECURELYWP_PATH . 'includes/captcha/captcha.php';
require_once SECURELYWP_PATH . 'includes/hardening/hide-wp-version.php';
require_once SECURELYWP_PATH . 'includes/hardening/disable-php-uploads.php';
require_once SECURELYWP_PATH . 'includes/hardening/disable-xmlrpc.php';
require_once SECURELYWP_PATH . 'includes/hardening/restrict-rest-api.php';
require_once SECURELYWP_PATH . 'includes/hardening/disable-emojis.php';
require_once SECURELYWP_PATH . 'includes/hardening/disable-embeds.php';
require_once SECURELYWP_PATH . 'includes/hardening/prevent-user-enum.php';
require_once SECURELYWP_PATH . 'includes/hardening/detect-admin-username.php';
require_once SECURELYWP_PATH . 'includes/hardening/disable-file-edit.php';
require_once SECURELYWP_PATH . 'includes/hardening/force-https.php';
require_once SECURELYWP_PATH . 'includes/hardening/brute-force-lite.php';
require_once SECURELYWP_PATH . 'includes/hardening/login-security.php';
require_once SECURELYWP_PATH . 'includes/headers/permissions-policy.php';
require_once SECURELYWP_PATH . 'includes/headers/csp.php';
require_once SECURELYWP_PATH . 'includes/headers/hsts.php';
require_once SECURELYWP_PATH . 'includes/headers/x-frame-options.php';
require_once SECURELYWP_PATH . 'includes/headers/referrer-policy.php';
require_once SECURELYWP_PATH . 'includes/headers/x-content-type-options.php';
require_once SECURELYWP_PATH . 'includes/two-factor/email-codes.php';
require_once SECURELYWP_PATH . 'includes/two-factor/totp.php';
require_once SECURELYWP_PATH . 'includes/two-factor/backup-codes.php';
require_once SECURELYWP_PATH . 'includes/two-factor/render.php';
require_once SECURELYWP_PATH . 'includes/firewall/firewall.php';
require_once SECURELYWP_PATH . 'admin/dashboard.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/vulnerability-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/system-details.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/hardening-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/captcha-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/headers-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/two-factor-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/firewall-settings.php';
require_once SECURELYWP_PATH . 'admin/settings-pages/login-security.php';
require_once SECURELYWP_PATH . 'includes/cache/purge-cache.php';

class SecurelyWP {
    private $vulnerability_scanner;

    public function __construct() {
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        register_uninstall_hook(__FILE__, [__CLASS__, 'uninstall']);
        add_action('plugins_loaded', [$this, 'bootstrap'], 0);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'filter_plugin_action_links']);
        add_filter('plugin_row_meta', [$this, 'filter_plugin_row_meta'], 10, 2);
        $this->vulnerability_scanner = new SecurelyWP_Vulnerability_Scanner();
        add_action('admin_menu', [$this, 'register_admin_menus']);
    }

    public function bootstrap() {
        securelywp_maybe_upgrade();
        securelywp_ensure_hardening_defaults();
        load_plugin_textdomain('securelywp', false, dirname(plugin_basename(__FILE__)) . '/languages/');
    }

    public function register_admin_menus() {
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('Firewall Settings', 'securelywp'),
            esc_html__('Firewall Settings', 'securelywp'),
            'manage_options',
            'securelywp-firewall-settings',
            'securelywp_firewall_settings_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('Security Headers', 'securelywp'),
            esc_html__('Security Headers', 'securelywp'),
            'manage_options',
            'securelywp-headers-settings',
            'securelywp_headers_settings_page'
        );
        add_submenu_page(
            'profile.php',
            esc_html__('Two-Factor Authentication', 'securelywp'),
            esc_html__('Two-Factor Authentication', 'securelywp'),
            'read',
            'securelywp-two-factor-settings',
            'securelywp_two_factor_settings_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('Security Hardening', 'securelywp'),
            esc_html__('Security Hardening', 'securelywp'),
            'manage_options',
            'securelywp-hardening-settings',
            'securelywp_hardening_settings_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('CAPTCHA Settings', 'securelywp'),
            esc_html__('CAPTCHA Settings', 'securelywp'),
            'manage_options',
            'securelywp-captcha-settings',
            'securelywp_captcha_settings_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('System Details', 'securelywp'),
            esc_html__('System Details', 'securelywp'),
            'manage_options',
            'securelywp-system-details',
            'securelywp_system_details_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('Vulnerability Scanner', 'securelywp'),
            esc_html__('Vulnerability Scanner', 'securelywp'),
            'manage_options',
            'securelywp-vulnerability-settings',
            'securelywp_vulnerability_settings_page'
        );
        add_submenu_page(
            'securelywp-dashboard',
            esc_html__('Login Security', 'securelywp'),
            esc_html__('Login Security', 'securelywp'),
            'manage_options',
            'securelywp-login-security',
            'securelywp_login_security_page'
        );
    }

    public function enqueue_assets($hook) {
        if ($hook !== 'profile.php' && strpos($hook, 'securelywp') === false) {
            return;
        }

        wp_enqueue_style(
            'securelywp-admin-css',
            SECURELYWP_URL . 'assets/css/admin.css',
            [],
            SECURELYWP_VERSION
        );

        wp_enqueue_script('jquery-ui-dialog');
        wp_enqueue_style('wp-jquery-ui-dialog');

        if ($hook === 'profile.php' || strpos($hook, 'securelywp-two-factor-settings') !== false) {
            wp_enqueue_script(
                'securelywp-qrcode-js',
                SECURELYWP_URL . 'assets/two-factor/js/qrcode.js',
                [],
                SECURELYWP_VERSION,
                true
            );
            wp_localize_script(
                'securelywp-qrcode-js',
                'securelywp_2fa',
                [
                    'ajax_url' => admin_url('admin-ajax.php'),
                    'nonce'    => wp_create_nonce('securelywp_2fa_nonce'),
                ]
            );
        }
    }

    public function filter_plugin_action_links($links) {
        foreach ($links as $key => $link) {
            if (strpos($link, 'View details') !== false || strpos($link, 'view details') !== false) {
                unset($links[$key]);
            }
        }

        return $links;
    }

    public function filter_plugin_row_meta($plugin_meta, $plugin_file) {
        if ($plugin_file !== plugin_basename(__FILE__)) {
            return $plugin_meta;
        }

        foreach ($plugin_meta as $key => $meta) {
            if (strpos($meta, 'View details') !== false || strpos($meta, 'view details') !== false) {
                unset($plugin_meta[$key]);
            }
        }

        return $plugin_meta;
    }

    public function activate() {
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
            'permissions_policy'               => 'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(self), encrypted-media=(), fullscreen=*, geolocation=(self), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=*, picture-in-picture=*, publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=*, usb=(), xr-spatial-tracking=(), gamepad=(), serial=()',
            'x_content_type_options_active'    => true,
            'x_content_type_options'           => true,
        ];
        $default_2fa_options = [
            'enforce_2fa_network' => false,
        ];
        $default_firewall_options = [
            'enable_firewall'     => true,
            'custom_rules'        => '',
            'whitelist'           => '',
            'check_request_uri'   => true,
            'check_query_string'  => true,
            'check_user_agent'    => true,
            'check_referrer'      => true,
            'check_post_body'     => true,
            'check_long_requests' => true,
        ];
        $default_vulnerability_options = [
            'auto_scan_enabled' => false,
            'auto_disable'      => false,
            'scan_frequency'    => 'weekly',
            'notify_email'      => sanitize_email(get_option('admin_email')),
        ];

        update_option('securelywp_options', []);
        update_option('securelywp_hardening_options', $default_hardening_options);
        update_option('securelywp_headers_options', $default_headers_options);
        update_option('securelywp_2fa_options', $default_2fa_options);
        update_option('securelywp_firewall_options', $default_firewall_options);
        update_option('securelywp_vulnerability_options', $default_vulnerability_options);
        update_option('securelywp_db_version', SECURELYWP_VERSION, false);

        $users = get_users(['fields' => 'ID']);
        foreach ($users as $user_id) {
            if (!get_user_meta($user_id, 'securelywp_2fa_user_options', true)) {
                update_user_meta($user_id, 'securelywp_2fa_user_options', [
                    'enable_totp'           => false,
                    'totp_secret'           => '',
                    'enable_email_2fa'      => false,
                    'enable_recovery_codes' => false,
                    'recovery_codes'        => [],
                    'primary_2fa_method'    => 'totp',
                    'totp_verified'         => false,
                ]);
            }
        }

        $scanner = new SecurelyWP_Vulnerability_Scanner();
        $scanner->schedule_scan();
    }

    public function deactivate() {
        delete_transient('securelywp_vulnerability_data');
        delete_transient('securelywp_vulnerability_scan_running');
        delete_transient('securelywp_wordfence_feed');
        wp_clear_scheduled_hook('securelywp_vulnerability_scan');
    }

    public static function uninstall() {
        delete_option('securelywp_options');
        delete_option('securelywp_hardening_options');
        delete_option('securelywp_headers_options');
        delete_option('securelywp_2fa_options');
        delete_option('securelywp_firewall_options');
        delete_option('securelywp_vulnerability_options');
        delete_option('securelywp_blocked_requests');
        delete_option('securelywp_cache_version');
        delete_option('securelywp_db_version');
        delete_transient('securelywp_vulnerability_data');
        delete_transient('securelywp_vulnerability_scan_running');
        delete_transient('securelywp_wordfence_feed');
        delete_transient('securelywp_system_details_cache');
        wp_clear_scheduled_hook('securelywp_vulnerability_scan');
    }
}

new SecurelyWP();
