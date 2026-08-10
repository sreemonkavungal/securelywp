<?php
/**
 * SecurelyWP Captcha - verification logic
 *
 * @package SecurelyWP
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Grab CAPTCHA token from POST.
 */
function securelywp_captcha_grab_token() {
    return isset($_POST['cf-turnstile-response']) ? sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'])) : apply_filters('securelywp_captcha_token_override', '');
}

/**
 * Verify token with Cloudflare Turnstile.
 */
function securelywp_captcha_verify_token($token) {
    if (!securelywp_captcha_is_configured() || empty($token)) {
        return !securelywp_captcha_is_configured();
    }
    $settings = securelywp_captcha_get_settings();
    $body = ['secret' => $settings['secret_key'], 'response' => $token];
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $body['remoteip'] = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
    }
    $resp = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
        'method' => 'POST',
        'timeout' => 8,
        'headers' => ['Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8'],
        'body' => $body,
        'data_format' => 'body',
    ]);
    if (is_wp_error($resp) || wp_remote_retrieve_response_code($resp) !== 200) {
        return false;
    }
    $payload = json_decode(wp_remote_retrieve_body($resp), true);
    return is_array($payload) && !empty($payload['success']);
}

/**
 * Failure message.
 */
function securelywp_captcha_fail_message() {
    return __('CAPTCHA verification failed.', 'securelywp');
}

/**
 * Register verification handlers.
 */
function securelywp_captcha_register_verifiers() {
    add_filter('authenticate', 'securelywp_captcha_verify_authenticate', 30, 3);
    add_filter('registration_errors', 'securelywp_captcha_verify_registration', 30, 3);
    add_filter('allow_password_reset', 'securelywp_captcha_verify_lostpassword', 30, 2);
    add_filter('preprocess_comment', 'securelywp_captcha_verify_comment', 30);
    if (function_exists('WC')) {
        add_action('woocommerce_after_checkout_validation', 'securelywp_captcha_verify_woocommerce_checkout', 30, 2);
    }
    if (defined('WPCF7_VERSION')) {
        add_action('wpcf7_before_send_mail', 'securelywp_captcha_cf7_verify');
    }
    if (class_exists('GFAPI')) {
        add_action('gform_pre_submission', 'securelywp_captcha_gf_verify');
    }
    if (class_exists('WPForms')) {
        add_action('wpforms_process', 'securelywp_captcha_wpforms_verify', 10, 3);
    }
    if (class_exists('FrmFormsController')) {
        add_action('frm_before_create_entry', 'securelywp_captcha_formidable_verify', 10, 2);
    }
    if (class_exists('Forminator_Form_Model')) {
        add_action('forminator_custom_form_submit_response', 'securelywp_captcha_forminator_verify', 10, 2);
    }
    if (class_exists('Elementor\Plugin')) {
        add_action('elementor_pro/forms/validation', 'securelywp_captcha_elementor_verify', 10, 2);
    }
    if (function_exists('edd_is_ajax')) {
        add_action('edd_checkout_error_checks', 'securelywp_captcha_edd_verify', 10, 1);
    }
    if (class_exists('MC4WP')) {
        add_filter('mc4wp_form_submit', 'securelywp_captcha_mailchimp_verify', 10, 2);
    }
    if (function_exists('bp_core_signup_user')) {
        add_action('bp_core_signup_user', 'securelywp_captcha_buddypress_verify', 1, 1);
    }
    if (function_exists('bbp_is_single_forum')) {
        add_action('bbp_new_reply', 'securelywp_captcha_bbpress_verify', 1, 2);
        add_action('bbp_new_topic', 'securelywp_captcha_bbpress_verify', 1, 2);
    }
    if (is_multisite()) {
        add_action('wpmu_validate_user_signup', 'securelywp_captcha_multisite_verify', 10, 1);
    }
}

function securelywp_captcha_verify_authenticate($user, $username, $password) {
    if (!securelywp_captcha_is_enabled_for('login') || is_wp_error($user)) {
        return $user;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        return new WP_Error('securelywp_captcha_failed', securelywp_captcha_fail_message());
    }
    return $user;
}

function securelywp_captcha_verify_registration($errors, $sanitized_user_login, $user_email) {
    if (!securelywp_captcha_is_enabled_for('register') || $errors->has_errors()) {
        return $errors;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        $errors->add('securelywp_captcha_failed', securelywp_captcha_fail_message());
    }
    return $errors;
}

function securelywp_captcha_verify_lostpassword($allowed, $user_data) {
    if (!securelywp_captcha_is_enabled_for('lostpassword') || is_wp_error($allowed)) {
        return $allowed;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        return new WP_Error('securelywp_captcha_failed', securelywp_captcha_fail_message());
    }
    return $allowed;
}

function securelywp_captcha_verify_comment($commentdata) {
    if (!securelywp_captcha_is_enabled_for('comment')) {
        return $commentdata;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
    return $commentdata;
}

function securelywp_captcha_verify_woocommerce_checkout($data, $errors) {
    if (!securelywp_captcha_is_enabled_for('checkout')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        $errors->add('securelywp_captcha_failed', securelywp_captcha_fail_message());
    }
}

function securelywp_captcha_cf7_verify($contact_form) {
    if (!securelywp_captcha_is_enabled_for('cf7')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        $submission = WPCF7_Submission::get_instance();
        if ($submission) {
            $submission->set_response(securelywp_captcha_fail_message());
            $submission->set_status('validation_failed');
        }
    }
}

function securelywp_captcha_gf_verify($form) {
    if (!securelywp_captcha_is_enabled_for('gravityforms')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        add_filter('gform_validation_message', function($message) {
            return '<div class="validation_error">' . esc_html(securelywp_captcha_fail_message()) . '</div>';
        });
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_wpforms_verify($fields, $entry, $form_data) {
    if (!securelywp_captcha_is_enabled_for('wpforms')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_formidable_verify($args, $form) {
    if (!securelywp_captcha_is_enabled_for('formidable')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_forminator_verify($data, $form_id) {
    if (!securelywp_captcha_is_enabled_for('forminator')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_elementor_verify($record, $ajax_handler) {
    if (!securelywp_captcha_is_enabled_for('elementor')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        if (is_object($record) && method_exists($record, 'add_error')) {
            $record->add_error(['message' => securelywp_captcha_fail_message()]);
        } else {
            wp_die(esc_html(securelywp_captcha_fail_message()), 403);
        }
    }
}

function securelywp_captcha_edd_verify($purchase_data) {
    if (!securelywp_captcha_is_enabled_for('edd')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_mailchimp_verify($continue, $form) {
    if (!securelywp_captcha_is_enabled_for('mailchimp4wp')) {
        return $continue;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        return false;
    }
    return $continue;
}

function securelywp_captcha_buddypress_verify($user_id) {
    if (!securelywp_captcha_is_enabled_for('buddypress')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_bbpress_verify($arg1 = null, $arg2 = null) {
    if (!securelywp_captcha_is_enabled_for('bbpress')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        wp_die(esc_html(securelywp_captcha_fail_message()), 403);
    }
}

function securelywp_captcha_multisite_verify($result) {
    if (!securelywp_captcha_is_enabled_for('multisite')) {
        return $result;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        if (is_array($result)) {
            if (empty($result['errors']) || !is_wp_error($result['errors'])) {
                $result['errors'] = new WP_Error();
            }
            $result['errors']->add('securelywp_captcha_failed', securelywp_captcha_fail_message());
        } else {
            wp_die(esc_html(securelywp_captcha_fail_message()), 403);
        }
    }
    return $result;
}

function securelywp_captcha_memberpress_verify($errors) {
    if (!securelywp_captcha_is_enabled_for('memberpress')) {
        return $errors;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        if (is_wp_error($errors)) {
            $errors->add('securelywp_captcha_failed', securelywp_captcha_fail_message());
        }
    }
    return $errors;
}

function securelywp_captcha_ultimatemember_verify($args) {
    if (!securelywp_captcha_is_enabled_for('ultimatemember')) {
        return;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        UM()->form()->add_error('securelywp_captcha_failed', securelywp_captcha_fail_message());
    }
}

function securelywp_captcha_wpmembers_verify($fields) {
    if (!securelywp_captcha_is_enabled_for('wp-members')) {
        return $fields;
    }
    $token = securelywp_captcha_grab_token();
    if (empty($token) || !securelywp_captcha_verify_token($token)) {
        global $wpmem;
        if (isset($wpmem) && is_object($wpmem)) {
            $wpmem->error = securelywp_captcha_fail_message();
        }
        return $fields;
    }
    return $fields;
}