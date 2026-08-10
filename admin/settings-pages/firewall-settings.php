<?php
/**
 * SecurelyWP Firewall Settings Page
 *
 * Handles the user settings page for firewall features.
 *
 * @package SecurelyWP
 * @since 1.0.8
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Render the firewall settings page.
 *
 * @return void
 */
function securelywp_firewall_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    $firewall_options = get_option('securelywp_firewall_options', [
        'enable_firewall' => true,
        'custom_rules' => '',
        'whitelist' => '',
        'check_request_uri' => true,
        'check_query_string' => true,
        'check_user_agent' => true,
        'check_referrer' => true,
        'check_post_body' => true,
        'check_long_requests' => true,
    ]);

    $message = '';
    $message_type = 'success';
    $regex_validation = [];

    // Handle form submission
    if (isset($_POST['securelywp_save_firewall_settings']) && check_admin_referer('securelywp_firewall_settings', '_wpnonce')) {
        $new_options = $firewall_options;

        $new_options['enable_firewall'] = isset($_POST['enable_firewall']);
        $new_options['custom_rules'] = isset($_POST['custom_rules']) ? sanitize_textarea_field($_POST['custom_rules']) : '';
        $new_options['whitelist'] = isset($_POST['whitelist']) ? sanitize_textarea_field($_POST['whitelist']) : '';
        $new_options['check_request_uri'] = isset($_POST['check_request_uri']);
        $new_options['check_query_string'] = isset($_POST['check_query_string']);
        $new_options['check_user_agent'] = isset($_POST['check_user_agent']);
        $new_options['check_referrer'] = isset($_POST['check_referrer']);
        $new_options['check_post_body'] = isset($_POST['check_post_body']);
        $new_options['check_long_requests'] = isset($_POST['check_long_requests']);

        // Validate custom rules
        $rules = explode("\n", $new_options['custom_rules']);
        foreach ($rules as $rule) {
            $rule = trim($rule);
            if (!empty($rule)) {
                $regex_validation[$rule] = securelywp_validate_regex($rule);
            }
        }

        if (in_array(false, $regex_validation, true)) {
            $message = esc_html__('Settings saved, but some custom rules are invalid and were ignored.', 'securelywp');
            $message_type = 'error';
        } else {
            $message = esc_html__('Firewall settings updated successfully!', 'securelywp');
        }

        update_option('securelywp_firewall_options', $new_options);
        $firewall_options = $new_options;
    }
    ?>
    <div class="wrap securelywp-dashboard securelywp-firewall-settings">
        <h1><?php esc_html_e('Firewall Settings', 'securelywp'); ?></h1>

        <?php if (!empty($message)): ?>
            <div class="notice notice-<?php echo esc_attr($message_type); ?> is-dismissible">
                <p><?php echo esc_html($message); ?></p>
            </div>
        <?php endif; ?>

        <div class="securelywp-card">
            <h2><?php esc_html_e('Firewall Settings', 'securelywp'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('securelywp_firewall_settings', '_wpnonce'); ?>
                
                <p>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="enable_firewall" <?php checked($firewall_options['enable_firewall']); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Enable Firewall (Recommended)', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Protects your site against malicious requests and known attack patterns.', 'securelywp'); ?></small>
                </p>
                <hr/>

                <p>
                    <label><?php esc_html_e('Inspection Layers', 'securelywp'); ?></label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_request_uri" <?php checked(!empty($firewall_options['check_request_uri'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Inspect request URI', 'securelywp'); ?>
                    </label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_query_string" <?php checked(!empty($firewall_options['check_query_string'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Inspect query strings', 'securelywp'); ?>
                    </label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_user_agent" <?php checked(!empty($firewall_options['check_user_agent'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Inspect user agents', 'securelywp'); ?>
                    </label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_referrer" <?php checked(!empty($firewall_options['check_referrer'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Inspect referrers', 'securelywp'); ?>
                    </label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_post_body" <?php checked(!empty($firewall_options['check_post_body'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Inspect POST bodies', 'securelywp'); ?>
                    </label>
                    <label class="securelywp-toggle">
                        <input type="checkbox" name="check_long_requests" <?php checked(!empty($firewall_options['check_long_requests'])); ?>>
                        <span class="slider"></span>
                        <?php esc_html_e('Block unusually long requests', 'securelywp'); ?>
                    </label>
                    <small><?php esc_html_e('Turn individual inspection layers on or off to tailor the firewall to your traffic patterns.', 'securelywp'); ?></small>
                </p>
                <hr/>

                <p>
                    <label for="custom_rules"><?php esc_html_e('Custom Rules', 'securelywp'); ?></label>
                    <textarea name="custom_rules" id="custom_rules" class="large-text" rows="5"><?php echo esc_textarea($firewall_options['custom_rules']); ?></textarea>
                    <small><?php esc_html_e('Enter one regex pattern per line to block specific requests.', 'securelywp'); ?></small>
                    <?php if (!empty($regex_validation)): ?>
                        <ul>
                            <?php foreach ($regex_validation as $rule => $valid): ?>
                                <li><?php echo esc_html($rule) . ': ' . ($valid ? esc_html__('Valid Rule', 'securelywp') : esc_html__('Invalid Regex', 'securelywp')); ?></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </p>
                <hr/>

                <p>
                    <label for="whitelist"><?php esc_html_e('Whitelist', 'securelywp'); ?></label>
                    <textarea name="whitelist" id="whitelist" class="large-text" rows="5"><?php echo esc_textarea($firewall_options['whitelist']); ?></textarea>
                    <small><?php esc_html_e('Enter one pattern per line to exclude from firewall checks (e.g., trusted IPs or user agents).', 'securelywp'); ?></small>
                </p>
                <hr/>

                <p>
                    <label><?php esc_html_e('Test Firewall', 'securelywp'); ?></label>
                    <a href="<?php echo esc_url(add_query_arg('securelywp_test', 'eval(', get_home_url())); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary securelywp-test-firewall"><?php esc_html_e('Test Firewall', 'securelywp'); ?></a>
                    <small><?php esc_html_e('Click to test if the firewall is working (should return a 403 Forbidden error).', 'securelywp'); ?></small>
                </p>
                <hr/>

                <p>
                    <label><?php esc_html_e('Recent Activity', 'securelywp'); ?></label>
                    <div class="recent-activity-area">
                        <?php
                        $blocked_requests = get_option('securelywp_blocked_requests', []);
                        if (empty($blocked_requests)): ?>
                            <p><?php esc_html_e('No blocked requests yet.', 'securelywp'); ?></p>
                        <?php else: ?>
                            <ul id="blocked-requests-list">
                                <?php foreach (array_reverse($blocked_requests) as $request): ?>
                                    <li><?php echo esc_html($request['time']) . ' - ' . esc_html($request['match']) . ' (IP: ' . esc_html($request['ip']) . ', URI: ' . esc_html($request['uri']) . ')'; ?></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                </p>

                <p class="submit">
                    <input type="submit" name="securelywp_save_firewall_settings" class="button button-primary" value="<?php esc_attr_e('Save Settings', 'securelywp'); ?>">
                </p>
            </form>
        </div>
    </div>
    <script>
    jQuery(document).ready(function($) {
        $('.securelywp-test-firewall').on('click', function(e) {
            e.preventDefault();
            var link = this;
            var dialog = $('<div class="securelywp-modal-dialog"><?php echo esc_js(__('This test opens a new tab. If the response is 403 Forbidden, the firewall is working.', 'securelywp')); ?></div>').dialog({
                title: '<?php echo esc_js(__('Confirm Test', 'securelywp')); ?>',
                buttons: {
                    '<?php echo esc_js(__('Okay, run the test.', 'securelywp')); ?>': function() {
                        window.open(link.href, '_blank');
                        $(this).dialog('close');
                    },
                    '<?php echo esc_js(__('Cancel', 'securelywp')); ?>': function() {
                        $(this).dialog('close');
                    }
                },
                modal: true,
                width: 370,
                closeText: ''
            });
        });
    });
    </script>
    <?php
}