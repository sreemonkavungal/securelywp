<?php
/**
 * SecurelyWP Dashboard
 *
 * @package SecurelyWP
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecurelyWP_Dashboard {
    public static function init() {
        add_action('admin_menu', [__CLASS__, 'register_menu']);
        add_action('wp_ajax_securelywp_get_dashboard_status', [__CLASS__, 'ajax_get_dashboard_status']);
    }

    public static function register_menu() {
        add_menu_page(
            esc_html__('SecurelyWP Dashboard', 'securelywp'),
            esc_html__('SecurelyWP', 'securelywp'),
            'manage_options',
            'securelywp-dashboard',
            [__CLASS__, 'render'],
            'dashicons-shield',
            30
        );
    }

    private static function get_status_data() {
        $hardening_options = get_option('securelywp_hardening_options', []);
        $headers_options = get_option('securelywp_headers_options', []);
        $captcha_options = securelywp_captcha_get_settings();
        $twofa_options = get_option('securelywp_2fa_options', []);
        $firewall_options = get_option('securelywp_firewall_options', ['enable_firewall' => true]);
        $login_security_options = securelywp_get_login_security_options();
        $vuln_summary = securelywp_get_vulnerability_summary();
        $blocked_requests = get_option('securelywp_blocked_requests', []);

        $hardening_enabled_count = count(array_filter($hardening_options));
        $hardening_total = count($hardening_options);
        $headers_enabled_count = count(array_filter([
            $headers_options['csp_active'] ?? false,
            $headers_options['hsts_active'] ?? false,
            $headers_options['x_frame_options_active'] ?? false,
            $headers_options['referrer_policy_active'] ?? false,
            $headers_options['permissions_policy_active'] ?? false,
            $headers_options['x_content_type_options_active'] ?? false,
        ]));
        $headers_total = 6;
        $captcha_enabled_count = count(array_filter($captcha_options, 'is_bool'));
        $captcha_total = max(0, count($captcha_options) - 2);
        $captcha_configured = !empty($captcha_options['site_key']) && !empty($captcha_options['secret_key']);
        $twofa_enabled_count = securelywp_count_users_with_2fa();
        $twofa_total = count(get_users(['fields' => 'ID']));
        $firewall_enabled = !empty($firewall_options['enable_firewall']);
        $login_security_enabled = !empty($login_security_options['enabled']);
        $login_security_duration = absint($login_security_options['lockout_duration']);
        $login_security_attempts = absint($login_security_options['max_attempts']);
        $login_security_recent_lockouts = count(securelywp_get_login_lockout_events());

        return [
            'vuln_status'         => $vuln_summary['scanning'] ? esc_html__('Scanning', 'securelywp') : esc_html__('Idle', 'securelywp'),
            'vuln_count'          => absint($vuln_summary['count']),
            'vuln_progress'       => $vuln_summary['scanning'] ? esc_html__('In progress', 'securelywp') : esc_html__('N/A', 'securelywp'),
            'vuln_indicator'      => $vuln_summary['scanning'] ? 'enabled' : ($vuln_summary['count'] > 0 ? 'infected' : 'idle'),
            'php_version'         => esc_html(phpversion()),
            'wp_version'          => esc_html(get_bloginfo('version')),
            'hardening_status'    => $hardening_enabled_count === $hardening_total
                ? esc_html__('All Enabled', 'securelywp')
                : esc_html(sprintf('%d/%d Enabled', $hardening_enabled_count, $hardening_total)),
            'hardening_count'     => esc_html("$hardening_enabled_count/$hardening_total"),
            'hardening_indicator' => $hardening_enabled_count === $hardening_total ? 'enabled' : ($hardening_enabled_count > 0 ? 'enabled' : 'disabled'),
            'headers_status'      => $headers_enabled_count === $headers_total
                ? esc_html__('All Enabled', 'securelywp')
                : esc_html(sprintf('%d/%d Enabled', $headers_enabled_count, $headers_total)),
            'headers_count'       => esc_html("$headers_enabled_count/$headers_total"),
            'headers_indicator'   => $headers_enabled_count === $headers_total ? 'enabled' : ($headers_enabled_count > 0 ? 'enabled' : 'disabled'),
            'captcha_status'      => ($captcha_configured && $captcha_enabled_count > 0)
                ? esc_html__('Enabled', 'securelywp')
                : esc_html__('Disabled', 'securelywp'),
            'captcha_count'       => esc_html("$captcha_enabled_count/$captcha_total"),
            'captcha_configured'  => $captcha_configured ? esc_html__('Yes', 'securelywp') : esc_html__('No', 'securelywp'),
            'captcha_indicator'   => ($captcha_configured && $captcha_enabled_count > 0) ? 'enabled' : 'disabled',
            'twofa_status'        => ($twofa_enabled_count > 0 || !empty($twofa_options['enforce_2fa_network']))
                ? esc_html__('Enabled', 'securelywp')
                : esc_html__('Disabled', 'securelywp'),
            'twofa_count'         => esc_html("$twofa_enabled_count/$twofa_total"),
            'twofa_enforced'      => !empty($twofa_options['enforce_2fa_network']) ? esc_html__('Yes', 'securelywp') : esc_html__('No', 'securelywp'),
            'twofa_indicator'     => ($twofa_enabled_count > 0 || !empty($twofa_options['enforce_2fa_network'])) ? 'enabled' : 'disabled',
            'firewall_status'     => $firewall_enabled ? esc_html__('Enabled', 'securelywp') : esc_html__('Disabled', 'securelywp'),
            'firewall_blocked'    => esc_html((string) count($blocked_requests)),
            'firewall_indicator'  => $firewall_enabled ? 'enabled' : 'disabled',
            'login_security_status' => $login_security_enabled ? esc_html__('Enabled', 'securelywp') : esc_html__('Disabled', 'securelywp'),
            'login_security_attempts' => esc_html((string) $login_security_attempts),
            'login_security_duration' => esc_html((string) $login_security_duration),
            'login_security_recent_lockouts' => esc_html((string) $login_security_recent_lockouts),
            'login_security_indicator' => $login_security_enabled ? 'enabled' : 'disabled',
        ];
    }

    public static function render() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
        }

        $data = self::get_status_data();
        ?>
        <div class="wrap securelywp-dashboard">
            <h1><?php esc_html_e('SecurelyWP Dashboard', 'securelywp'); ?></h1>
            <p class="securelywp-dashboard-intro"><?php esc_html_e('Monitor your site’s security posture, track protection status, and reach important controls from a modern, business-grade dashboard.', 'securelywp'); ?></p>
            <div class="securelywp-summary-shell">
                <button type="button" class="securelywp-summary-nav securelywp-summary-nav-prev" aria-label="Scroll left">&#10094;</button>
                <div class="securelywp-summary-grid" id="securelywp-summary-grid" tabindex="0">
                    <div class="securelywp-summary-card">
                        <span class="summary-label"><?php esc_html_e('Vulnerability Scanner', 'securelywp'); ?></span>
                        <strong class="summary-value"><?php echo absint($data['vuln_count']); ?></strong>
                        <span class="summary-note"><?php esc_html_e('Issues found and active scan state.', 'securelywp'); ?></span>
                        <span class="summary-pill summary-pill-<?php echo esc_attr($data['vuln_indicator']); ?>"><?php echo esc_html($data['vuln_status']); ?></span>
                    </div>
                    <div class="securelywp-summary-card">
                        <span class="summary-label"><?php esc_html_e('Firewall', 'securelywp'); ?></span>
                        <strong class="summary-value"><?php echo esc_html($data['firewall_blocked']); ?></strong>
                        <span class="summary-note"><?php esc_html_e('Blocked requests kept out of your site.', 'securelywp'); ?></span>
                        <span class="summary-pill summary-pill-<?php echo esc_attr($data['firewall_indicator']); ?>"><?php echo esc_html($data['firewall_status']); ?></span>
                    </div>
                    <div class="securelywp-summary-card">
                        <span class="summary-label"><?php esc_html_e('Security Headers', 'securelywp'); ?></span>
                        <strong class="summary-value"><?php echo esc_html($data['headers_count']); ?></strong>
                        <span class="summary-note"><?php esc_html_e('Headers currently protecting your site.', 'securelywp'); ?></span>
                        <span class="summary-pill summary-pill-<?php echo esc_attr($data['headers_indicator']); ?>"><?php echo esc_html($data['headers_status']); ?></span>
                    </div>
                    <div class="securelywp-summary-card">
                        <span class="summary-label"><?php esc_html_e('Two-Factor Auth', 'securelywp'); ?></span>
                        <strong class="summary-value"><?php echo esc_html($data['twofa_count']); ?></strong>
                        <span class="summary-note"><?php esc_html_e('Users with 2FA enabled on the site.', 'securelywp'); ?></span>
                        <span class="summary-pill summary-pill-<?php echo esc_attr($data['twofa_indicator']); ?>"><?php echo esc_html($data['twofa_status']); ?></span>
                    </div>
                    <div class="securelywp-summary-card">
                        <span class="summary-label"><?php esc_html_e('Login Security', 'securelywp'); ?></span>
                        <strong class="summary-value"><?php echo esc_html($data['login_security_attempts']); ?></strong>
                        <span class="summary-note"><?php esc_html_e('Failed attempts before lockout kicks in.', 'securelywp'); ?></span>
                        <span class="summary-pill summary-pill-<?php echo esc_attr($data['login_security_indicator']); ?>"><?php echo esc_html($data['login_security_status']); ?></span>
                    </div>
                </div>
                <button type="button" class="securelywp-summary-nav securelywp-summary-nav-next" aria-label="Scroll right">&#10095;</button>
            </div>
            <div class="securelywp-dashboard-grid">
                <div class="securelywp-card" data-feature="vuln-scanner">
                    <h2><?php esc_html_e('Vulnerability Scanner', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['vuln_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="vuln_status"><?php echo esc_html($data['vuln_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Issues Found:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="vuln_count"><?php echo absint($data['vuln_count']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('Progress:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="vuln_progress"><?php echo esc_html($data['vuln_progress']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-vulnerability-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="firewall-settings">
                    <h2><?php esc_html_e('Firewall', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['firewall_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="firewall_status"><?php echo esc_html($data['firewall_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Blocked Requests:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="firewall_blocked"><?php echo esc_html($data['firewall_blocked']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-firewall-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="system-details">
                    <h2><?php esc_html_e('System Details', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator enabled"></span>
                        <span><?php esc_html_e('Active', 'securelywp'); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('PHP Version:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="php_version"><?php echo esc_html($data['php_version']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('WP Version:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="wp_version"><?php echo esc_html($data['wp_version']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-system-details')); ?>" class="button"><?php esc_html_e('View Details', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="hardening-settings">
                    <h2><?php esc_html_e('Hardening Settings', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['hardening_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="hardening_status"><?php echo esc_html($data['hardening_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Features:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="hardening_count"><?php echo esc_html($data['hardening_count']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-hardening-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="headers-settings">
                    <h2><?php esc_html_e('Security Headers', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['headers_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="headers_status"><?php echo esc_html($data['headers_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Headers:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="headers_count"><?php echo esc_html($data['headers_count']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-headers-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="captcha-settings">
                    <h2><?php esc_html_e('CAPTCHA Settings', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['captcha_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="captcha_status"><?php echo esc_html($data['captcha_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Forms Protected:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="captcha_count"><?php echo esc_html($data['captcha_count']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('Configured:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="captcha_configured"><?php echo esc_html($data['captcha_configured']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-captcha-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="login-security">
                    <h2><?php esc_html_e('Login Security', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['login_security_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="login_security_status"><?php echo esc_html($data['login_security_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Lockout Threshold:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="login_security_attempts"><?php echo esc_html($data['login_security_attempts']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('Lockout Duration:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="login_security_duration"><?php echo esc_html($data['login_security_duration']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('Recent Lockouts:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="login_security_recent_lockouts"><?php echo esc_html($data['login_security_recent_lockouts']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=securelywp-login-security')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
                <div class="securelywp-card" data-feature="twofa-settings">
                    <h2><?php esc_html_e('Two-Factor Authentication', 'securelywp'); ?></h2>
                    <div class="feature-status">
                        <span class="status-indicator <?php echo esc_attr($data['twofa_indicator']); ?>"></span>
                        <span class="dynamic-data" data-field="twofa_status"><?php echo esc_html($data['twofa_status']); ?></span>
                    </div>
                    <ul>
                        <li><strong><?php esc_html_e('Users with 2FA:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="twofa_count"><?php echo esc_html($data['twofa_count']); ?></span>
                        </li>
                        <li><strong><?php esc_html_e('Network Enforced:', 'securelywp'); ?></strong>
                            <span class="dynamic-data" data-field="twofa_enforced"><?php echo esc_html($data['twofa_enforced']); ?></span>
                        </li>
                    </ul>
                    <a href="<?php echo esc_url(admin_url('profile.php?page=securelywp-two-factor-settings')); ?>" class="button"><?php esc_html_e('Manage', 'securelywp'); ?></a>
                </div>
            </div>
            <?php wp_nonce_field('securelywp_nonce', 'securelywp_nonce_field', false); ?>
            <script>
            jQuery(document).ready(function($) {
                var $summaryTrack = $('#securelywp-summary-grid');
                var summaryCardWidth = $summaryTrack.find('.securelywp-summary-card').first().outerWidth(true);

                function scrollSummaryBy(delta) {
                    $summaryTrack.animate({ scrollLeft: '+=' + delta }, 220);
                }

                $('.securelywp-summary-nav-prev').on('click', function() {
                    scrollSummaryBy(-summaryCardWidth);
                });

                $('.securelywp-summary-nav-next').on('click', function() {
                    scrollSummaryBy(summaryCardWidth);
                });

                $summaryTrack.on('keydown', function(event) {
                    if (event.key === 'ArrowLeft') {
                        event.preventDefault();
                        scrollSummaryBy(-summaryCardWidth);
                    }
                    if (event.key === 'ArrowRight') {
                        event.preventDefault();
                        scrollSummaryBy(summaryCardWidth);
                    }
                });

                function updateDashboard() {
                    $.ajax({
                        url: ajaxurl,
                        method: 'POST',
                        data: {
                            action: 'securelywp_get_dashboard_status',
                            nonce: $('#securelywp_nonce_field').val()
                        },
                        success: function(response) {
                            if (!response.success) {
                                return;
                            }

                            var data = response.data;
                            $('[data-field="vuln_status"]').text(data.vuln_status);
                            $('[data-field="vuln_count"]').text(data.vuln_count);
                            $('[data-field="vuln_progress"]').text(data.vuln_progress);
                            $('[data-feature="vuln-scanner"] .status-indicator').removeClass('enabled infected idle').addClass(data.vuln_indicator);
                            $('[data-field="firewall_status"]').text(data.firewall_status);
                            $('[data-field="firewall_blocked"]').text(data.firewall_blocked);
                            $('[data-feature="firewall-settings"] .status-indicator').removeClass('enabled disabled').addClass(data.firewall_indicator);
                            $('[data-field="php_version"]').text(data.php_version);
                            $('[data-field="wp_version"]').text(data.wp_version);
                            $('[data-field="hardening_status"]').text(data.hardening_status);
                            $('[data-field="hardening_count"]').text(data.hardening_count);
                            $('[data-feature="hardening-settings"] .status-indicator').removeClass('enabled disabled').addClass(data.hardening_indicator);
                            $('[data-field="headers_status"]').text(data.headers_status);
                            $('[data-field="headers_count"]').text(data.headers_count);
                            $('[data-feature="headers-settings"] .status-indicator').removeClass('enabled disabled').addClass(data.headers_indicator);
                            $('[data-field="captcha_status"]').text(data.captcha_status);
                            $('[data-field="captcha_count"]').text(data.captcha_count);
                            $('[data-field="captcha_configured"]').text(data.captcha_configured);
                            $('[data-feature="captcha-settings"] .status-indicator').removeClass('enabled disabled').addClass(data.captcha_indicator);
                            $('[data-field="twofa_status"]').text(data.twofa_status);
                            $('[data-field="twofa_count"]').text(data.twofa_count);
                            $('[data-field="twofa_enforced"]').text(data.twofa_enforced);
                            $('[data-feature="twofa-settings"] .status-indicator').removeClass('enabled disabled').addClass(data.twofa_indicator);
                            $('[data-field="login_security_status"]').text(data.login_security_status);
                            $('[data-field="login_security_attempts"]').text(data.login_security_attempts);
                            $('[data-field="login_security_duration"]').text(data.login_security_duration);
                            $('[data-field="login_security_recent_lockouts"]').text(data.login_security_recent_lockouts);
                            $('[data-feature="login-security"] .status-indicator').removeClass('enabled disabled').addClass(data.login_security_indicator);
                        }
                    });
                }
                updateDashboard();
                setInterval(updateDashboard, 5000);
            });
            </script>
        <?php
    }

    public static function ajax_get_dashboard_status() {
        if (!check_ajax_referer('securelywp_nonce', 'nonce', false) || !current_user_can('manage_options')) {
            wp_send_json_error(['message' => esc_html__('Unauthorized.', 'securelywp')]);
        }

        wp_send_json_success(self::get_status_data());
    }
}

SecurelyWP_Dashboard::init();
