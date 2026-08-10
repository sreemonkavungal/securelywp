<?php
/**
 * SecurelyWP Two-Factor Authentication Settings Page
 *
 * Handles the user settings page for two-factor authentication features.
 *
 * @package SecurelyWP
 * @since 1.0.8
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Render the 2FA settings page.
 *
 * @return void
 */
function securelywp_two_factor_settings_page() {
    if (!current_user_can('read')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $current_user = wp_get_current_user();
    $user_2fa_options = get_user_meta($current_user->ID, 'securelywp_2fa_user_options', true) ?: [
        'enable_totp' => false,
        'totp_secret' => '',
        'totp_verified' => false,
        'enable_email_2fa' => false,
        'enable_recovery_codes' => false,
        'recovery_codes' => [],
        'primary_2fa_method' => 'totp',
    ];

    $message = '';
    $message_type = 'success';

    // Handle form submission for generating new recovery codes
    if (isset($_POST['securelywp_generate_recovery_codes']) && check_admin_referer('securelywp_2fa_settings', '_wpnonce')) {
        $codes = securelywp_generate_recovery_codes();
        $user_2fa_options['recovery_codes'] = $codes['hashed'];
        $user_2fa_options['enable_recovery_codes'] = true;
        update_user_meta($current_user->ID, 'securelywp_2fa_user_options', $user_2fa_options);
        securelywp_store_recovery_codes_for_display($current_user->ID, $codes['plain']);
        $message = esc_html__('New recovery codes generated successfully! Please save them in a safe place.', 'securelywp');

    // Handle form submission for saving settings
    } elseif (isset($_POST['securelywp_save_2fa_settings']) && check_admin_referer('securelywp_2fa_settings', '_wpnonce')) {
        $new_options = $user_2fa_options; // Start with existing options

        $new_options['enable_totp'] = isset($_POST['enable_totp']);
        $new_options['enable_email_2fa'] = isset($_POST['enable_email_2fa']);
        $new_options['enable_recovery_codes'] = isset($_POST['enable_recovery_codes']);
        $new_options['primary_2fa_method'] = in_array($_POST['primary_2fa_method'], ['totp', 'email', 'backup_codes']) ? sanitize_text_field($_POST['primary_2fa_method']) : 'totp';
        
        // Generate recovery codes automatically on first enable
        if ($new_options['enable_recovery_codes'] && empty($user_2fa_options['recovery_codes'])) {
            $codes = securelywp_generate_recovery_codes();
            $new_options['recovery_codes'] = $codes['hashed'];
            securelywp_store_recovery_codes_for_display($current_user->ID, $codes['plain']);
        }

        // Handle TOTP verification
        if ($new_options['enable_totp'] && !empty($_POST['totp_code'])) {
            $totp_secret = !empty($new_options['totp_secret']) ? $new_options['totp_secret'] : securelywp_generate_totp_secret();
            if (securelywp_verify_totp_code($totp_secret, sanitize_text_field($_POST['totp_code']))) {
                $new_options['totp_secret'] = $totp_secret;
                $new_options['totp_verified'] = true;
                $message = esc_html__('Authenticator app enabled successfully!', 'securelywp');
            } else {
                $message = esc_html__('Invalid TOTP code. Settings were saved, but the authenticator app remains disabled until verified.', 'securelywp');
                $message_type = 'error';
                $new_options['enable_totp'] = false;
                $new_options['totp_verified'] = false;
            }
        } elseif ($new_options['enable_totp'] && empty($user_2fa_options['totp_secret'])) {
            $new_options['totp_secret'] = securelywp_generate_totp_secret();
            $new_options['totp_verified'] = false;
        } elseif (!$new_options['enable_totp']) {
            $new_options['totp_secret'] = '';
            $new_options['totp_verified'] = false;
        }

        // Handle network-wide enforcement (super admins only)
        if (is_multisite() && is_super_admin()) {
            $global_2fa_options = get_option('securelywp_2fa_options', []);
            $global_2fa_options['enforce_2fa_network'] = isset($_POST['enforce_2fa_network']);
            update_option('securelywp_2fa_options', $global_2fa_options);
        }

        update_user_meta($current_user->ID, 'securelywp_2fa_user_options', $new_options);
        
        if (empty($message)) {
            $message = esc_html__('Settings updated successfully!', 'securelywp');
        }
        $user_2fa_options = $new_options; // Refresh options for display
    }

    $totp_secret = !empty($user_2fa_options['totp_secret']) ? $user_2fa_options['totp_secret'] : securelywp_generate_totp_secret();
    $totp_uri = securelywp_generate_totp_uri($current_user->user_login, $totp_secret);
    ?>
    <div class="wrap securelywp-dashboard securelywp-two-factor-settings">
        <h1><?php esc_html_e('Two-Factor Authentication', 'securelywp'); ?></h1>

        <?php if (!empty($message)): ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?> is-dismissible">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>

        <div class="securelywp-card">
            <h2><?php esc_html_e('Two-Factor Authentication Settings', 'securelywp'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('securelywp_2fa_settings', '_wpnonce'); ?>
                
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="enable_totp" <?php checked($user_2fa_options['enable_totp']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Enable Authenticator App (Recommended)', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Use an app like Google Authenticator or Authy.', 'securelywp'); ?></small>
                    <?php if ($user_2fa_options['enable_totp']): ?>
                        <div class="securelywp-totp-setup">
                            <p><?php esc_html_e('Scan this QR code with your authenticator app:', 'securelywp'); ?></p>
                            <div id="securelywp-qrcode"></div>
                            <p><?php esc_html_e('Or enter this secret manually:', 'securelywp'); ?> <strong><?php echo esc_html($totp_secret); ?></strong></p>
                            <p>
                                <label for="totp_code"><?php esc_html_e('Verify by entering the code from your app:', 'securelywp'); ?></label>
                                <input type="text" name="totp_code" id="totp_code" class="regular-text" placeholder="123456" autocomplete="off">
                            </p>
                            <script>
                                jQuery(document).ready(function($) {
                                    new QRCode(document.getElementById('securelywp-qrcode'), '<?php echo esc_js($totp_uri); ?>');
                                });
                            </script>
                        </div>
                    <?php endif; ?>
                </p>
                <hr/>
                
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="enable_email_2fa" <?php checked($user_2fa_options['enable_email_2fa']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Enable Email 2FA', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Receive authentication codes to your registered email.', 'securelywp'); ?></small>
                </p>
                <hr/>

                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="enable_recovery_codes" <?php checked($user_2fa_options['enable_recovery_codes']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Enable Recovery Codes', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Emergency codes for account access if other methods fail.', 'securelywp'); ?></small>
                    <?php if ($user_2fa_options['enable_recovery_codes']): ?>
                        <?php if (!empty($display_recovery_codes)) : ?>
                        <div class="recovery-codes-area">
                            <p><strong><?php esc_html_e('Your recovery codes (save these securely):', 'securelywp'); ?></strong></p>
                            <ul id="recovery-codes-list">
                                <?php foreach ($display_recovery_codes as $code) : ?>
                                    <li><?php echo esc_html($code); ?></li>
                                <?php endforeach; ?>
                            </ul>
                            <button type="button" class="button button-secondary" id="copy-codes"><?php esc_html_e('Copy Codes', 'securelywp'); ?></button>
                            <button type="button" class="button button-secondary" id="download-codes"><?php esc_html_e('Download Codes', 'securelywp'); ?></button>
                        </div>
                        <?php endif; ?>
                        <p><input type="submit" name="securelywp_generate_recovery_codes" class="button button-secondary" value="<?php esc_attr_e('Generate New Recovery Codes', 'securelywp'); ?>"></p>
                    <?php endif; ?>
                </p>
                <hr/>

                <p>
                    <label for="primary_2fa_method"><?php esc_html_e('Primary 2FA Method', 'securelywp'); ?></label>
                    <select name="primary_2fa_method" id="primary_2fa_method">
                        <option value="totp" <?php selected($user_2fa_options['primary_2fa_method'], 'totp'); ?>><?php esc_html_e('Authenticator App', 'securelywp'); ?></option>
                        <option value="email" <?php selected($user_2fa_options['primary_2fa_method'], 'email'); ?>><?php esc_html_e('Email', 'securelywp'); ?></option>
                        <option value="backup_codes" <?php selected($user_2fa_options['primary_2fa_method'], 'backup_codes'); ?>><?php esc_html_e('Recovery Codes', 'securelywp'); ?></option>
                    </select>
                    <small><?php esc_html_e('Select your preferred default method for 2FA.', 'securelywp'); ?></small>
                </p>

                <?php if (is_multisite() && is_super_admin()): ?>
                    <p>
                        <label class="securelywp-toggle">
                            <input type="checkbox" name="enforce_2fa_network" <?php checked(get_option('securelywp_2fa_options')['enforce_2fa_network'] ?? false); ?>>
                            <span class="slider"></span>
                            <?php esc_html_e('Enforce 2FA Network-Wide', 'securelywp'); ?>
                        </label>
                        <small><?php esc_html_e('Require all users on the network to enable 2FA.', 'securelywp'); ?></small>
                    </p>
                <?php endif; ?>

                <p class="submit">
                    <input type="submit" name="securelywp_save_2fa_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
                </p>
            </form>
        </div>
    </div>
    <script>
    jQuery(document).ready(function($) {
        $('#copy-codes').on('click', function() {
            var codes = $('#recovery-codes-list li').map(function() { return $(this).text(); }).get().join('\n');
            navigator.clipboard.writeText(codes).then(function() {
                alert('<?php echo esc_js(__("Recovery codes copied to clipboard!", "securelywp")); ?>');
            });
        });

        $('#download-codes').on('click', function() {
            var codes = $('#recovery-codes-list li').map(function() { return $(this).text(); }).get().join('\n');
            var blob = new Blob([codes], { type: 'text/plain' });
            var link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'securelywp-recovery-codes.txt';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    });
    </script>
    <?php
}