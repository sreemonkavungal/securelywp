<?php
/**
 * SecurelyWP Headers Settings Page
 *
 * Handles the admin settings page for security headers.
 *
 * @package SecurelyWP
 * @since 1.0.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Render the headers settings page.
 *
 * @return void
 */
function securelywp_headers_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $options = get_option('securelywp_headers_options', [
        'csp_active' => true,
        'csp' => "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; upgrade-insecure-requests;",
        'csp_report_uri' => '',
        'hsts_active' => true,
        'hsts_max_age' => 31536000,
        'hsts_include_subdomains' => true,
        'hsts_preload' => true,
        'x_frame_options_active' => true,
        'x_frame_options' => 'SAMEORIGIN',
        'x_frame_options_allow_from_url' => '',
        'referrer_policy_active' => true,
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'permissions_policy_active' => true,
        'permissions_policy' => 'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(self), encrypted-media=(), fullscreen=*, geolocation=(self), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=*, picture-in-picture=*, publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=*, usb=(), xr-spatial-tracking=(), gamepad=(), serial=()',
        'x_content_type_options_active' => true,
        'x_content_type_options' => true,
        'coop_active' => true,
        'coop' => 'same-origin',
    ]);

    $message = '';
    $message_type = 'success';

    // Handle form submission
    if (isset($_POST['securelywp_save_headers_settings'])) {
        if (!check_admin_referer('securelywp_headers_settings', '_wpnonce')) {
            $message = esc_html__('Security check failed. Please try again.', 'securelywp');
            $message_type = 'error';
        } else {
            $new_options = [
                'csp_active' => isset($_POST['csp_active']) && filter_var($_POST['csp_active'], FILTER_VALIDATE_BOOLEAN),
                'csp' => isset($_POST['csp']) ? sanitize_text_field($_POST['csp']) : 'upgrade-insecure-requests;',
                'csp_report_uri' => isset($_POST['csp_report_uri']) ? esc_url_raw($_POST['csp_report_uri']) : '',
                'hsts_active' => isset($_POST['hsts_active']) && filter_var($_POST['hsts_active'], FILTER_VALIDATE_BOOLEAN),
                'hsts_max_age' => isset($_POST['hsts_max_age']) ? absint($_POST['hsts_max_age']) : 31536000,
                'hsts_include_subdomains' => isset($_POST['hsts_include_subdomains']) && filter_var($_POST['hsts_include_subdomains'], FILTER_VALIDATE_BOOLEAN),
                'hsts_preload' => isset($_POST['hsts_preload']) && filter_var($_POST['hsts_preload'], FILTER_VALIDATE_BOOLEAN),
                'x_frame_options_active' => isset($_POST['x_frame_options_active']) && filter_var($_POST['x_frame_options_active'], FILTER_VALIDATE_BOOLEAN),
                'x_frame_options' => isset($_POST['x_frame_options']) ? strtoupper(sanitize_text_field($_POST['x_frame_options'])) : 'SAMEORIGIN',
                'x_frame_options_allow_from_url' => isset($_POST['x_frame_options_allow_from_url']) ? esc_url_raw($_POST['x_frame_options_allow_from_url']) : '',
                'referrer_policy_active' => isset($_POST['referrer_policy_active']) && filter_var($_POST['referrer_policy_active'], FILTER_VALIDATE_BOOLEAN),
                'referrer_policy' => isset($_POST['referrer_policy']) ? sanitize_text_field($_POST['referrer_policy']) : 'strict-origin-when-cross-origin',
                'permissions_policy_active' => isset($_POST['permissions_policy_active']) && filter_var($_POST['permissions_policy_active'], FILTER_VALIDATE_BOOLEAN),
                'permissions_policy' => isset($_POST['permissions_policy']) ? sanitize_text_field($_POST['permissions_policy']) : 'accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(self), encrypted-media=(), fullscreen=*, geolocation=(self), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=*, picture-in-picture=*, publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=*, usb=(), xr-spatial-tracking=(), gamepad=(), serial=()',
                'x_content_type_options_active' => isset($_POST['x_content_type_options_active']) && filter_var($_POST['x_content_type_options_active'], FILTER_VALIDATE_BOOLEAN),
                'x_content_type_options' => isset($_POST['x_content_type_options']) && filter_var($_POST['x_content_type_options'], FILTER_VALIDATE_BOOLEAN),
                'coop_active' => isset($_POST['coop_active']) && filter_var($_POST['coop_active'], FILTER_VALIDATE_BOOLEAN),
                'coop' => isset($_POST['coop']) ? sanitize_text_field($_POST['coop']) : 'same-origin',
            ];
            if (update_option('securelywp_headers_options', $new_options)) {
                $message = esc_html__('Settings updated successfully!', 'securelywp');
            } else {
                $message = esc_html__('No changes were made to the settings.', 'securelywp');
                $message_type = 'info';
            }
            $options = $new_options; // Update local options to reflect changes
        }
    }

    ?>
    <div class="wrap securelywp-dashboard securelywp-headers-settings">
        <h1><?php esc_html_e('Security Headers', 'securelywp'); ?></h1>

        <?php if (!empty($message)): ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?>">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>

        <div class="securelywp-card">
            <h2><?php esc_html_e('Security Headers Settings', 'securelywp'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('securelywp_headers_settings'); ?>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="csp_active" <?php checked($options['csp_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Content Security Policy', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Controls which resources the browser can load. Example: "default-src \'self\'; script-src \'self\' https://example.com;" restricts scripts to your domain and example.com.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('Content Security Policy Directives', 'securelywp'); ?></label>
                    <input type="text" name="csp" value="<?php echo esc_attr($options['csp']); ?>" placeholder="upgrade-insecure-requests;">
                    <small><?php esc_html_e('Specify the Content Security Policy directives.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('CSP Report URI', 'securelywp'); ?></label>
                    <input type="text" name="csp_report_uri" value="<?php echo esc_attr($options['csp_report_uri']); ?>" placeholder="https://example.com/report-uri">
                    <small><?php esc_html_e('URL to receive CSP violation reports, e.g., https://your-report-uri.com.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="hsts_active" <?php checked($options['hsts_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('HTTP Strict Transport Security', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Forces browsers to use HTTPS. Example: "max-age=31536000; includeSubDomains" ensures HTTPS for one year, including subdomains.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('HSTS Max Age', 'securelywp'); ?></label>
                    <input type="number" name="hsts_max_age" value="<?php echo esc_attr($options['hsts_max_age']); ?>" min="0">
                    <small><?php esc_html_e('Duration in seconds for HSTS policy (default: 31536000, one year).', 'securelywp'); ?></small>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="hsts_include_subdomains" <?php checked($options['hsts_include_subdomains']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('HSTS Include Subdomains', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Applies HSTS to all subdomains, e.g., sub.example.com.', 'securelywp'); ?></small>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="hsts_preload" <?php checked($options['hsts_preload']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('HSTS Preload', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Allows browsers to preload HSTS, e.g., for inclusion in Chrome’s HSTS preload list.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="x_frame_options_active" <?php checked($options['x_frame_options_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('X-Frame-Options', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Prevents clickjacking by controlling framing. Example: "SAMEORIGIN" allows framing only by your own site.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('X-Frame-Options Value', 'securelywp'); ?></label>
                    <select name="x_frame_options">
                        <option value="DENY" <?php selected($options['x_frame_options'], 'DENY'); ?>><?php esc_html_e('DENY', 'securelywp'); ?></option>
                        <option value="SAMEORIGIN" <?php selected($options['x_frame_options'], 'SAMEORIGIN'); ?>><?php esc_html_e('SAMEORIGIN', 'securelywp'); ?></option>
                        <option value="ALLOW-FROM" <?php selected($options['x_frame_options'], 'ALLOW-FROM'); ?>><?php esc_html_e('ALLOW-FROM', 'securelywp'); ?></option>
                    </select>
                    <small><?php esc_html_e('Control framing of your site.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('Allow From URL', 'securelywp'); ?></label>
                    <input type="text" name="x_frame_options_allow_from_url" value="<?php echo esc_attr($options['x_frame_options_allow_from_url']); ?>" placeholder="https://example.com">
                    <small><?php esc_html_e('Specify URL for ALLOW-FROM directive, e.g., https://example.com.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="referrer_policy_active" <?php checked($options['referrer_policy_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Referrer Policy', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Controls referrer information in requests. Example: "strict-origin-when-cross-origin" sends the origin only for same-origin or HTTPS cross-origin requests.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('Referrer Policy Value', 'securelywp'); ?></label>
                    <select name="referrer_policy">
                        <?php
                        $policies = [
                            'no-referrer',
                            'no-referrer-when-downgrade',
                            'origin',
                            'origin-when-cross-origin',
                            'same-origin',
                            'strict-origin',
                            'strict-origin-when-cross-origin',
                            'unsafe-url'
                        ];
                        foreach ($policies as $policy) {
                            echo '<option value="' . esc_attr($policy) . '" ' . selected($options['referrer_policy'], $policy, false) . '>' . esc_html($policy) . '</option>';
                        }
                        ?>
                    </select>
                    <small><?php esc_html_e('Control referrer information sent with requests.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="permissions_policy_active" <?php checked($options['permissions_policy_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Permissions Policy', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Restricts browser features. Example: "geolocation=(self), camera=()" allows geolocation for your site but blocks camera access.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('Permissions Policy Directives', 'securelywp'); ?></label>
                    <input type="text" name="permissions_policy" value="<?php echo esc_attr($options['permissions_policy']); ?>" placeholder="accelerometer=(), autoplay=(), camera=(), ...">
                    <small><?php esc_html_e('Specify permissions policy directives.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="x_content_type_options_active" <?php checked($options['x_content_type_options_active']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('X-Content-Type-Options', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Prevents MIME-type sniffing. Example: "nosniff" ensures browsers respect the declared Content-Type.', 'securelywp'); ?></small>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="x_content_type_options" <?php checked($options['x_content_type_options']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('X-Content-Type-Options: nosniff', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Prevents MIME-type sniffing to avoid security risks from misinterpreted content types.', 'securelywp'); ?></small>
                </p>
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="coop_active" <?php checked(!empty($options['coop_active'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Cross-Origin-Opener-Policy', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Reduces cross-window attacks by limiting how your site can be opened from other origins.', 'securelywp'); ?></small>
                    <label><?php esc_html_e('COOP Value', 'securelywp'); ?></label>
                    <select name="coop">
                        <option value="same-origin" <?php selected($options['coop'] ?? 'same-origin', 'same-origin'); ?>>same-origin</option>
                        <option value="same-origin-allow-popups" <?php selected($options['coop'] ?? 'same-origin', 'same-origin-allow-popups'); ?>>same-origin-allow-popups</option>
                        <option value="unsafe-none" <?php selected($options['coop'] ?? 'same-origin', 'unsafe-none'); ?>>unsafe-none</option>
                    </select>
                </p>
                <input type="submit" name="securelywp_save_headers_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
            </form>
            <?php $static_rules = securelywp_get_static_header_rules(); ?>
            <div class="securelywp-card" style="margin-top:24px;">
                <h2><?php esc_html_e('Static Header Rules', 'securelywp'); ?></h2>
                <p><?php esc_html_e('Use these rules in your web server configuration to apply security headers outside of PHP.', 'securelywp'); ?></p>
                <p><strong><?php esc_html_e('Apache / LiteSpeed', 'securelywp'); ?></strong></p>
                <textarea readonly rows="6" class="large-text code"><?php echo esc_textarea($static_rules['apache']); ?></textarea>
                <p><strong><?php esc_html_e('Nginx', 'securelywp'); ?></strong></p>
                <textarea readonly rows="6" class="large-text code"><?php echo esc_textarea($static_rules['nginx']); ?></textarea>
                <button type="button" class="button securelywp-copy-headers"><?php esc_html_e('Copy Rules', 'securelywp'); ?></button>
            </div>
        </div>
    </div>
    <?php
}