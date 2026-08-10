<?php
/**
 * SecurelyWP 2FA Render Handler
 *
 * @package SecurelyWP
 * @since 1.0.8
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('login_form', function () {
    $user_id = securelywp_2fa_get_pending_user_id();
    if (!$user_id) {
        return;
    }

    $user = get_userdata($user_id);
    if (!$user) {
        securelywp_2fa_clear_pending_user();
        return;
    }

    $user_2fa_options = get_user_meta($user_id, 'securelywp_2fa_user_options', true) ?: [];

    if (!securelywp_2fa_is_required($user_2fa_options)) {
        securelywp_2fa_clear_pending_user();
        return;
    }

    $method = securelywp_2fa_resolve_method($user_2fa_options);
    if ($method === 'none') {
        securelywp_2fa_clear_pending_user();
        return;
    }

    if ($method === 'email' && !empty($user_2fa_options['enable_email_2fa'])) {
        securelywp_generate_email_code($user_id);
    }

    $error = isset($_POST['securelywp_2fa_code']) && !isset($_POST['securelywp_resend_code'])
        ? esc_html__('Invalid 2FA code. Please try again.', 'securelywp')
        : '';
    ?>
    <div class="securelywp-2fa-challenge" style="margin-top: 20px;">
        <p>
            <label for="securelywp_2fa_code">
                <?php
                if ($method === 'totp') {
                    esc_html_e('Enter the code from your authenticator app:', 'securelywp');
                } elseif ($method === 'email') {
                    esc_html_e('Enter the code sent to your email:', 'securelywp');
                } else {
                    esc_html_e('Enter a recovery code:', 'securelywp');
                }
                ?>
            </label>
            <input type="text" name="securelywp_2fa_code" id="securelywp_2fa_code" class="input" value="" size="20" placeholder="123456" autocomplete="off">
        </p>
        <?php if ($error) : ?>
            <p class="error"><?php echo esc_html($error); ?></p>
        <?php endif; ?>
        <?php if ($method === 'email') : ?>
            <p>
                <input type="submit" name="securelywp_resend_code" class="button button-secondary" value="<?php esc_attr_e('Resend Code', 'securelywp'); ?>">
            </p>
        <?php endif; ?>
        <?php wp_nonce_field('securelywp_2fa_challenge', 'securelywp_2fa_nonce'); ?>
    </div>
    <?php
});

add_filter('authenticate', function ($user, $username, $password) {
    if (is_wp_error($user) || !($user instanceof WP_User)) {
        return $user;
    }

    $user_2fa_options = get_user_meta($user->ID, 'securelywp_2fa_user_options', true) ?: [];

    if (!securelywp_2fa_is_required($user_2fa_options)) {
        return $user;
    }

    securelywp_2fa_set_pending_user($user->ID);

    if (isset($_POST['securelywp_2fa_code'], $_POST['securelywp_2fa_nonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['securelywp_2fa_nonce'])), 'securelywp_2fa_challenge')) {
        $code = sanitize_text_field(wp_unslash($_POST['securelywp_2fa_code']));
        $method = securelywp_2fa_resolve_method($user_2fa_options);

        if ($method === 'none') {
            securelywp_2fa_clear_pending_user();
            return $user;
        }

        $valid = false;
        if ($method === 'totp' && !empty($user_2fa_options['enable_totp']) && !empty($user_2fa_options['totp_verified']) && !empty($user_2fa_options['totp_secret'])) {
            $valid = securelywp_verify_totp_code($user_2fa_options['totp_secret'], $code);
        } elseif ($method === 'email' && !empty($user_2fa_options['enable_email_2fa'])) {
            $valid = securelywp_verify_email_code($user->ID, $code);
        } elseif ($method === 'backup_codes' && !empty($user_2fa_options['enable_recovery_codes'])) {
            $valid = securelywp_verify_recovery_code($user->ID, $code);
        }

        if ($valid) {
            securelywp_2fa_clear_pending_user();
            return $user;
        }

        return new WP_Error('invalid_2fa_code', esc_html__('Invalid 2FA code. Please try again.', 'securelywp'));
    }

    if (isset($_POST['securelywp_resend_code'], $_POST['securelywp_2fa_nonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['securelywp_2fa_nonce'])), 'securelywp_2fa_challenge')) {
        if (!empty($user_2fa_options['enable_email_2fa'])) {
            securelywp_generate_email_code($user->ID);
        }
        return new WP_Error('2fa_required', esc_html__('Please enter your 2FA code.', 'securelywp'));
    }

    return new WP_Error('2fa_required', esc_html__('Please enter your 2FA code.', 'securelywp'));
}, 100, 3);

add_action('wp_ajax_securelywp_reset_2fa', function () {
    check_ajax_referer('securelywp_2fa_nonce', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => esc_html__('Insufficient permissions.', 'securelywp')]);
    }

    $user_id = absint($_POST['user_id']);
    delete_user_meta($user_id, 'securelywp_2fa_user_options');
    wp_send_json_success(['message' => esc_html__('2FA reset successfully.', 'securelywp')]);
});
