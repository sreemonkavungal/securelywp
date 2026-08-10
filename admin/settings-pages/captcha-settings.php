<?php
/**
 * SecurelyWP CAPTCHA Settings Page
 *
 * Handles the admin settings page for CAPTCHA integration.
 *
 * @package SecurelyWP
 * @since 1.0.6
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Render CAPTCHA settings page.
 */
function securelywp_captcha_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $options = securelywp_captcha_get_settings();
    $message = '';
    $message_type = 'success';

    if (isset($_POST['securelywp_save_captcha_settings']) && check_admin_referer('securelywp_captcha_settings')) {
        $new_options = [
            'site_key' => isset($_POST['turnstile_site_key']) ? sanitize_text_field(wp_unslash($_POST['turnstile_site_key'])) : '',
            'secret_key' => isset($_POST['turnstile_secret_key']) ? sanitize_text_field(wp_unslash($_POST['turnstile_secret_key'])) : '',
            'login' => isset($_POST['captcha_login']),
            'register' => isset($_POST['captcha_register']),
            'lostpassword' => isset($_POST['captcha_lostpassword']),
            'comment' => isset($_POST['captcha_comment']),
            'checkout' => isset($_POST['captcha_checkout']) && function_exists('WC'),
            'wpforms' => isset($_POST['captcha_wpforms']) && class_exists('WPForms'),
            'gravityforms' => isset($_POST['captcha_gravityforms']) && class_exists('GFAPI'),
            'cf7' => isset($_POST['captcha_cf7']) && defined('WPCF7_VERSION'),
            'formidable' => isset($_POST['captcha_formidable']) && class_exists('FrmFormsController'),
            'forminator' => isset($_POST['captcha_forminator']) && class_exists('Forminator_Form_Model'),
            'elementor' => isset($_POST['captcha_elementor']) && class_exists('Elementor\Plugin'),
            'edd' => isset($_POST['captcha_edd']) && function_exists('edd_is_ajax'),
            'mailchimp4wp' => isset($_POST['captcha_mailchimp4wp']) && class_exists('MC4WP'),
            'buddypress' => isset($_POST['captcha_buddypress']) && function_exists('bp_core_signup_user'),
            'bbpress' => isset($_POST['captcha_bbpress']) && function_exists('bbp_is_single_forum'),
            'memberpress' => isset($_POST['captcha_memberpress']) && class_exists('MeprUser'),
            'ultimatemember' => isset($_POST['captcha_ultimatemember']) && class_exists('UM'),
            'wp-members' => isset($_POST['captcha_wp-members']) && defined('WPMEMBERS_VERSION'),
            'multisite' => isset($_POST['captcha_multisite']) && is_multisite(),
        ];

        if (update_option(SECURELYWP_CAPTCHA_OPTION, $new_options)) {
            $message = esc_html__('Settings updated!', 'securelywp');
        } else {
            $message = esc_html__('No changes made.', 'securelywp');
            $message_type = 'info';
        }
        $options = securelywp_captcha_get_settings();
    }

    ?>
    <div class="wrap securelywp-captcha-settings">
        <h1><?php esc_html_e('CAPTCHA Settings', 'securelywp'); ?></h1>
        <?php if ($message): ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?>">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>
        <div class="securelywp-card">
            <h2><?php esc_html_e('Cloudflare Turnstile', 'securelywp'); ?></h2>
            <form method="post">
                <?php wp_nonce_field('securelywp_captcha_settings'); ?>
                <p>
                    <label for="turnstile_site_key"><?php esc_html_e('Site Key', 'securelywp'); ?></label><br>
                    <input type="text" name="turnstile_site_key" id="turnstile_site_key" value="<?php echo esc_attr($options['site_key']); ?>" class="regular-text">
                    <small><?php esc_html_e('Cloudflare Turnstile Site Key.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label for="turnstile_secret_key"><?php esc_html_e('Secret Key', 'securelywp'); ?></label><br>
                    <input type="text" name="turnstile_secret_key" id="turnstile_secret_key" value="<?php echo esc_attr($options['secret_key']); ?>" class="regular-text">
                    <small><?php esc_html_e('Cloudflare Turnstile Secret Key.', 'securelywp'); ?></small>
                </p>
                <h3><?php esc_html_e('Enable CAPTCHA For', 'securelywp'); ?></h3>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="captcha_login" <?php checked($options['login']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Login Form', 'securelywp'); ?>
                    </label>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="captcha_register" <?php checked($options['register']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Registration Form', 'securelywp'); ?>
                    </label>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="captcha_lostpassword" <?php checked($options['lostpassword']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Lost Password Form', 'securelywp'); ?>
                    </label>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="captcha_comment" <?php checked($options['comment']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Comment Form', 'securelywp'); ?>
                    </label>
                </p>
                <?php if (function_exists('WC')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_checkout" <?php checked($options['checkout']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('WooCommerce Checkout', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (defined('WPCF7_VERSION')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_cf7" <?php checked($options['cf7']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Contact Form 7', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('GFAPI')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_gravityforms" <?php checked($options['gravityforms']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Gravity Forms', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('WPForms')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_wpforms" <?php checked($options['wpforms']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('WPForms', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('FrmFormsController')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_formidable" <?php checked($options['formidable']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Formidable Forms', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('Forminator_Form_Model')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_forminator" <?php checked($options['forminator']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Forminator', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('Elementor\Plugin')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_elementor" <?php checked($options['elementor']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Elementor Pro Forms', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (function_exists('edd_is_ajax')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_edd" <?php checked($options['edd']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Easy Digital Downloads', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('MC4WP')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_mailchimp4wp" <?php checked($options['mailchimp4wp']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Mailchimp for WP', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (function_exists('bp_core_signup_user')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_buddypress" <?php checked($options['buddypress']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('BuddyPress', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (function_exists('bbp_is_single_forum')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_bbpress" <?php checked($options['bbpress']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('bbPress', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('MeprUser')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_memberpress" <?php checked($options['memberpress']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('MemberPress', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (class_exists('UM')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_ultimatemember" <?php checked($options['ultimatemember']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Ultimate Member', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (defined('WPMEMBERS_VERSION')): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_wp-members" <?php checked($options['wp-members']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('WP-Members', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if (is_multisite()): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="captcha_multisite" <?php checked($options['multisite']); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Multisite Signup', 'securelywp'); ?>
                        </label>
                    </p>
                <?php endif; ?>
                <input type="submit" name="securelywp_save_captcha_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
            </form>
        </div>
    </div>
    <?php
}