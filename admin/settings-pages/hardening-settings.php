<?php
/**
 * SecurelyWP Hardening Settings Page
 *
 * Handles the admin settings page for security hardening features.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Render the hardening settings page.
 *
 * @return void
 */
function securelywp_hardening_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $options = wp_parse_args(
        get_option('securelywp_hardening_options', []),
        [
            'hide_wp_version' => false,
            'disable_php_uploads' => false,
            'prevent_user_enum' => false,
            'detect_admin_username' => false,
            'disable_file_edit' => false,
            'force_https' => false,
            'disable_xmlrpc' => false,
            'restrict_rest_api' => false,
            'disable_emojis' => false,
            'disable_embeds' => false,
            'brute_force_protection' => false,
        ]
    );

    $message = '';
    $message_type = 'success';

    // Handle form submission
    if (isset($_POST['securelywp_save_hardening_settings'])) {
        if (!check_admin_referer('securelywp_hardening_settings', '_wpnonce')) {
            $message = esc_html__('Security check failed. Please try again.', 'securelywp');
            $message_type = 'error';
        } else {
            $new_options = [
                'hide_wp_version' => isset($_POST['hide_wp_version']) && filter_var($_POST['hide_wp_version'], FILTER_VALIDATE_BOOLEAN),
                'disable_php_uploads' => isset($_POST['disable_php_uploads']) && filter_var($_POST['disable_php_uploads'], FILTER_VALIDATE_BOOLEAN),
                'prevent_user_enum' => isset($_POST['prevent_user_enum']) && filter_var($_POST['prevent_user_enum'], FILTER_VALIDATE_BOOLEAN),
                'detect_admin_username' => isset($_POST['detect_admin_username']) && filter_var($_POST['detect_admin_username'], FILTER_VALIDATE_BOOLEAN),
                'disable_file_edit' => isset($_POST['disable_file_edit']) && filter_var($_POST['disable_file_edit'], FILTER_VALIDATE_BOOLEAN),
                'force_https' => isset($_POST['force_https']) && filter_var($_POST['force_https'], FILTER_VALIDATE_BOOLEAN),
                'disable_xmlrpc' => isset($_POST['disable_xmlrpc']) && filter_var($_POST['disable_xmlrpc'], FILTER_VALIDATE_BOOLEAN),
                'restrict_rest_api' => isset($_POST['restrict_rest_api']) && filter_var($_POST['restrict_rest_api'], FILTER_VALIDATE_BOOLEAN),
                'disable_emojis' => isset($_POST['disable_emojis']) && filter_var($_POST['disable_emojis'], FILTER_VALIDATE_BOOLEAN),
                'disable_embeds' => isset($_POST['disable_embeds']) && filter_var($_POST['disable_embeds'], FILTER_VALIDATE_BOOLEAN),
                'brute_force_protection' => isset($_POST['brute_force_protection']) && filter_var($_POST['brute_force_protection'], FILTER_VALIDATE_BOOLEAN),
            ];
            if (update_option('securelywp_hardening_options', $new_options)) {
                $message = esc_html__('Settings updated successfully!', 'securelywp');
            } else {
                $message = esc_html__('No changes were made to the settings.', 'securelywp');
                $message_type = 'info';
            }
            $options = $new_options; // Update local options to reflect changes
        }
    }

    ?>
    <div class="wrap securelywp-dashboard securelywp-hardening-settings">
        <h1><?php esc_html_e('Security Hardening', 'securelywp'); ?></h1>

        <?php if (!empty($message)): ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?>">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>

        <div class="securelywp-card">
            <h2><?php esc_html_e('Hardening Settings', 'securelywp'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('securelywp_hardening_settings'); ?>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="hide_wp_version" <?php checked($options['hide_wp_version']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Hide WordPress Version', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Removes version information from meta tags and assets to prevent version-specific attacks.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="disable_php_uploads" <?php checked($options['disable_php_uploads']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Disable PHP Execution in Uploads', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Prevents execution of PHP scripts in the uploads directory.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="prevent_user_enum" <?php checked($options['prevent_user_enum']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Prevent User Enumeration', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Blocks attempts to enumerate usernames via author queries.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="detect_admin_username" <?php checked($options['detect_admin_username']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Detect Admin Username', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Warns if an "admin" username exists, a common brute-force target.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="disable_file_edit" <?php checked($options['disable_file_edit']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Disable File Editing in Dashboard', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Disables theme and plugin file editors in the dashboard.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="force_https" <?php checked($options['force_https']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Force HTTPS for Login & Admin', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Ensures admin and login pages use HTTPS to protect credentials.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="disable_xmlrpc" <?php checked($options['disable_xmlrpc']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Disable XML-RPC', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Turn off XML-RPC to reduce attack surface and improve performance.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="restrict_rest_api" <?php checked($options['restrict_rest_api']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Restrict REST API to Authenticated Users', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Requires login for REST API requests, blocking anonymous access.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="disable_emojis" <?php checked($options['disable_emojis']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Disable Emojis', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Removes emoji scripts/styles for faster page loads across the site.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="disable_embeds" <?php checked($options['disable_embeds']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Disable Embeds', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Disables oEmbed discovery and embed routes for a leaner site.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="brute_force_protection" <?php checked($options['brute_force_protection']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Basic Brute Force Protection', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Limits login attempts per IP to prevent brute force attacks.', 'securelywp'); ?></small>
                </p>
                <input type="submit" name="securelywp_save_hardening_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
            </form>
        </div>
    </div>
    <?php
}