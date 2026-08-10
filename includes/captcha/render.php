<?php
/**
 * SecurelyWP Captcha - render + enqueue
 *
 * @package SecurelyWP
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Enqueue Turnstile script.
 */
function securelywp_captcha_enqueue_script() {
    if (!securelywp_captcha_is_configured() || wp_script_is('securelywp-turnstile', 'enqueued')) {
        return;
    }
    wp_enqueue_script(
        'securelywp-turnstile',
        'https://challenges.cloudflare.com/turnstile/v0/api.js',
        [],
        null,
        true
    );
}
add_action('wp_enqueue_scripts', 'securelywp_captcha_enqueue_script');
add_action('login_enqueue_scripts', 'securelywp_captcha_enqueue_script');

/**
 * Render CAPTCHA widget.
 */
function securelywp_captcha_render($context = 'generic') {
    if (!securelywp_captcha_is_configured() || !securelywp_captcha_is_enabled_for($context)) {
        return;
    }
    $settings = securelywp_captcha_get_settings();
    $site_key = esc_attr($settings['site_key']);
    $ctx = esc_attr($context);
    securelywp_captcha_enqueue_script();
    echo "<div class='securelywp-captcha-wrap securelywp-captcha-$ctx'><div class='cf-turnstile' data-sitekey='$site_key' data-action='$ctx' data-theme='auto'></div></div>";
}

/**
 * Context-specific render functions.
 */
function securelywp_captcha_render_login() { securelywp_captcha_render('login'); }
function securelywp_captcha_render_register() { securelywp_captcha_render('register'); }
function securelywp_captcha_render_lostpassword() { securelywp_captcha_render('lostpassword'); }
function securelywp_captcha_render_comment() { securelywp_captcha_render('comment'); }
function securelywp_captcha_render_checkout() { securelywp_captcha_render('checkout'); }

/**
 * Contact Form 7 render.
 */
function securelywp_captcha_cf7_render($content) {
    if (!securelywp_captcha_is_enabled_for('cf7')) {
        return $content;
    }
    $insert = securelywp_captcha_get_widget_html('cf7');
    return strpos($content, '</form>') !== false ? str_replace('</form>', $insert . '</form>', $content) : $content . $insert;
}

/**
 * Get widget HTML.
 */
function securelywp_captcha_get_widget_html($context = 'generic') {
    if (!securelywp_captcha_is_configured() || !securelywp_captcha_is_enabled_for($context)) {
        return '';
    }
    $settings = securelywp_captcha_get_settings();
    $site_key = esc_attr($settings['site_key']);
    $ctx = esc_attr($context);
    return "<div class='securelywp-captcha-wrap securelywp-captcha-$ctx'><div class='cf-turnstile' data-sitekey='$site_key' data-action='$ctx' data-theme='auto'></div></div>";
}

/**
 * Gravity Forms render.
 */
function securelywp_captcha_gf_render($form) {
    if (!securelywp_captcha_is_enabled_for('gravityforms') || !isset($form['fields']) || !is_array($form['fields'])) {
        return $form;
    }
    $form['fields'][] = [
        'type' => 'html',
        'content' => securelywp_captcha_get_widget_html('gravityforms'),
        'id' => uniqid('securelywp_gf_'),
    ];
    return $form;
}

/**
 * WPForms render.
 */
function securelywp_captcha_wpforms_render($content, $form_data = null) {
    if (!securelywp_captcha_is_enabled_for('wpforms')) {
        return $content;
    }
    $insert = securelywp_captcha_get_widget_html('wpforms');
    return strpos($content, '</form>') !== false ? str_replace('</form>', $insert . '</form>', $content) : $content . $insert;
}

/**
 * Formidable render.
 */
function securelywp_captcha_formidable_render($content, $form) {
    if (!securelywp_captcha_is_enabled_for('formidable')) {
        return $content;
    }
    return $content . securelywp_captcha_get_widget_html('formidable');
}

/**
 * Forminator render.
 */
function securelywp_captcha_forminator_render($html, $form_id) {
    if (!securelywp_captcha_is_enabled_for('forminator')) {
        return $html;
    }
    return $html . securelywp_captcha_get_widget_html('forminator');
}