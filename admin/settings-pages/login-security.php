<?php
/**
 * SecurelyWP Login Security Settings Page
 *
 * Handles login protection settings for repeated failed logins.
 *
 * @package SecurelyWP
 * @since 1.2.2
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Render the login security settings page.
 *
 * @return void
 */
function securelywp_login_security_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $options = securelywp_get_login_security_options();
    $message = '';
    $message_type = 'success';

    if (isset($_POST['securelywp_save_login_security_settings'])) {
        if (!check_admin_referer('securelywp_login_security_settings', '_wpnonce')) {
            $message = esc_html__('Security check failed. Please try again.', 'securelywp');
            $message_type = 'error';
        } else {
            $new_options = [
                'enabled'           => isset($_POST['login_security_enabled']) && filter_var($_POST['login_security_enabled'], FILTER_VALIDATE_BOOLEAN),
                'max_attempts'      => max(1, absint($_POST['max_attempts'])),
                'lockout_duration'  => max(1, absint($_POST['lockout_duration'])),
                'lockout_message'   => sanitize_text_field(wp_unslash($_POST['lockout_message'])),
            ];

            if (update_option('securelywp_login_security_options', $new_options)) {
                $message = esc_html__('Login security settings updated successfully!', 'securelywp');
            } else {
                $message = esc_html__('No changes were made to the settings.', 'securelywp');
                $message_type = 'info';
            }

            $options = $new_options;
        }
    }

    ?>
    <div class="wrap securelywp-dashboard securelywp-login-security-settings">
        <h1><?php esc_html_e('Login Security', 'securelywp'); ?></h1>

        <?php if (!empty($message)) : ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?>">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>

        <div class="securelywp-card">
            <h2><?php esc_html_e('Protect logins from repeated password guessing', 'securelywp'); ?></h2>
            <p><?php esc_html_e('This protection blocks repeated failed logins from the same IP address after a configurable threshold is reached.', 'securelywp'); ?></p>

            <form method="post" action="">
                <?php wp_nonce_field('securelywp_login_security_settings'); ?>

                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="login_security_enabled" <?php checked($options['enabled']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Enable Login Protection', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Turn this on to block excessive failed login attempts automatically.', 'securelywp'); ?></small>
                </p>

                <p>
                    <label for="max_attempts"><?php esc_html_e('Maximum failed attempts before lockout', 'securelywp'); ?></label>
                    <input type="number" id="max_attempts" name="max_attempts" min="1" max="50" value="<?php echo esc_attr($options['max_attempts']); ?>">
                    <small><?php esc_html_e('Example: 5 means the user will be blocked after 5 failed attempts.', 'securelywp'); ?></small>
                </p>

                <p>
                    <label for="lockout_duration"><?php esc_html_e('Lockout duration (minutes)', 'securelywp'); ?></label>
                    <input type="number" id="lockout_duration" name="lockout_duration" min="1" max="1440" value="<?php echo esc_attr($options['lockout_duration']); ?>">
                    <small><?php esc_html_e('The account or IP will stay blocked for this many minutes.', 'securelywp'); ?></small>
                </p>

                <p>
                    <label for="lockout_message"><?php esc_html_e('Lockout message', 'securelywp'); ?></label>
                    <input type="text" id="lockout_message" name="lockout_message" value="<?php echo esc_attr($options['lockout_message']); ?>">
                    <small><?php esc_html_e('Message shown when a user is temporarily blocked.', 'securelywp'); ?></small>
                </p>

                <input type="submit" name="securelywp_save_login_security_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
            </form>
        </div>
    </div>
    <?php
}


            