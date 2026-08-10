<?php
/**
 * SecurelyWP Captcha - bootstrap loader
 *
 * @package SecurelyWP
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('SECURELYWP_CAPTCHA_OPTION')) {
    define('SECURELYWP_CAPTCHA_OPTION', 'securelywp_captcha_settings');
}

require_once __DIR__ . '/render.php';
require_once __DIR__ . '/verify.php';

/**
 * Check if Turnstile is configured.
 */
function securelywp_captcha_is_configured() {
    $settings = securelywp_captcha_get_settings();
    return !empty($settings['site_key']) && !empty($settings['secret_key']);
}

/**
 * Get CAPTCHA settings.
 */
function securelywp_captcha_get_settings() {
    $defaults = [
        'site_key' => '',
        'secret_key' => '',
        'login' => true,
        'register' => true,
        'lostpassword' => true,
        'comment' => true,
        'checkout' => true,
        'wpforms' => true,
        'gravityforms' => true,
        'cf7' => true,
        'formidable' => true,
        'forminator' => true,
        'elementor' => true,
        'edd' => true,
        'mailchimp4wp' => true,
        'buddypress' => true,
        'bbpress' => true,
        'memberpress' => true,
        'ultimatemember' => true,
        'wp-members' => true,
        'multisite' => true,
    ];
    $saved = get_option(SECURELYWP_CAPTCHA_OPTION, []);
    return wp_parse_args(is_array($saved) ? $saved : [], $defaults);
}

/**
 * Check if CAPTCHA is enabled for a context.
 */
function securelywp_captcha_is_enabled_for($context) {
    $context = (string) $context;
    $settings = securelywp_captcha_get_settings();
    $enabled = isset($settings[$context]) ? (bool) $settings[$context] : false;
    return apply_filters('securelywp_captcha_enabled_for', $enabled, $context);
}

/**
 * Register hooks and integrations.
 */
add_action('plugins_loaded', function () {
    if (!securelywp_captcha_is_configured()) {
        return;
    }

    $settings = securelywp_captcha_get_settings();

    if (securelywp_captcha_is_enabled_for('login')) {
        add_action('login_form', 'securelywp_captcha_render_login');
    }
    if (securelywp_captcha_is_enabled_for('register')) {
        add_action('register_form', 'securelywp_captcha_render_register');
    }
    if (securelywp_captcha_is_enabled_for('lostpassword')) {
        add_action('lostpassword_form', 'securelywp_captcha_render_lostpassword');
    }
    if (securelywp_captcha_is_enabled_for('comment')) {
        add_action('comment_form_after_fields', 'securelywp_captcha_render_comment');
        add_action('comment_form_logged_in_after', 'securelywp_captcha_render_comment');
    }
    if (securelywp_captcha_is_enabled_for('checkout') && function_exists('WC')) {
        add_action('woocommerce_checkout_before_customer_details', 'securelywp_captcha_render_checkout');
    }
    if ($settings['cf7'] && defined('WPCF7_VERSION')) {
        add_filter('wpcf7_form_elements', 'securelywp_captcha_cf7_render');
        add_action('wpcf7_before_send_mail', 'securelywp_captcha_cf7_verify');
    }
    if ($settings['gravityforms'] && class_exists('GFAPI')) {
        add_filter('gform_pre_render', 'securelywp_captcha_gf_render');
        add_action('gform_pre_submission', 'securelywp_captcha_gf_verify');
    }
    if ($settings['wpforms'] && class_exists('WPForms')) {
        add_filter('wpforms_frontend_output', 'securelywp_captcha_wpforms_render', 10, 2);
        add_action('wpforms_process', 'securelywp_captcha_wpforms_verify', 10, 3);
    }
    if ($settings['formidable'] && class_exists('FrmFormsController')) {
        add_filter('frm_display_form', 'securelywp_captcha_formidable_render', 10, 2);
        add_action('frm_before_create_entry', 'securelywp_captcha_formidable_verify', 10, 2);
    }
    if ($settings['forminator'] && class_exists('Forminator_Form_Model')) {
        add_filter('forminator_custom_form_render_response', 'securelywp_captcha_forminator_render', 10, 2);
        add_action('forminator_custom_form_submit_response', 'securelywp_captcha_forminator_verify', 10, 2);
    }
    if ($settings['elementor'] && class_exists('Elementor\Plugin')) {
        add_action('elementor_pro/forms/validation', 'securelywp_captcha_elementor_verify', 10, 2);
    }
    if ($settings['edd'] && function_exists('edd_is_ajax')) {
        add_action('edd_purchase_form_before_submit', 'securelywp_captcha_render_checkout');
        add_action('edd_checkout_error_checks', 'securelywp_captcha_edd_verify', 10, 1);
    }
    if ($settings['mailchimp4wp'] && class_exists('MC4WP')) {
        add_action('mc4wp_form_before_fields', 'securelywp_captcha_render');
        add_filter('mc4wp_form_submit', 'securelywp_captcha_mailchimp_verify', 10, 2);
    }
    if ($settings['buddypress'] && function_exists('bp_core_signup_user')) {
        add_action('bp_before_account_details_fields', 'securelywp_captcha_render');
        add_action('bp_core_signup_user', 'securelywp_captcha_buddypress_verify', 1, 1);
    }
    if ($settings['bbpress'] && function_exists('bbp_is_single_forum')) {
        add_action('bbp_template_after_replies_loop', 'securelywp_captcha_render');
        add_action('bbp_new_reply', 'securelywp_captcha_bbpress_verify', 1, 2);
        add_action('bbp_new_topic', 'securelywp_captcha_bbpress_verify', 1, 2);
    }
    if ($settings['memberpress'] && class_exists('MeprUser')) {
        add_action('mepr-account-form', 'securelywp_captcha_render');
    }
    if ($settings['ultimatemember'] && class_exists('UM')) {
        add_action('um_after_form_fields', 'securelywp_captcha_render');
    }
    if ($settings['wp-members'] && defined('WPMEMBERS_VERSION')) {
        add_action('wpmem_register_form', 'securelywp_captcha_render');
    }
    if ($settings['multisite'] && is_multisite()) {
        add_action('signup_extra_fields', 'securelywp_captcha_render');
        add_action('wpmu_validate_user_signup', 'securelywp_captcha_multisite_verify', 10, 1);
    }
    if ($settings['memberpress'] && class_exists('MeprUser')) {
        add_action('mepr-validate-signup', 'securelywp_captcha_memberpress_verify');
    }
    if ($settings['ultimatemember'] && class_exists('UM')) {
        add_action('um_submit_form_errors_hook_', 'securelywp_captcha_ultimatemember_verify', 10, 1);
    }
    if ($settings['wp-members'] && defined('WPMEMBERS_VERSION')) {
        add_filter('wpmem_register_filter', 'securelywp_captcha_wpmembers_verify');
    }

    securelywp_captcha_register_verifiers();
});