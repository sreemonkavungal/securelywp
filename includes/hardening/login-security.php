<?php
/**
 * SecurelyWP Login Security Protection
 *
 * Adds configurable failed-login lockout protection.
 *
 * @package SecurelyWP
 * @since 1.2.2
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecurelyWP_Login_Security {
    /**
     * Constructor.
     */
    public function __construct() {
        add_action('wp_login_failed', [$this, 'track_failed_login'], 10, 1);
        add_action('wp_login', [$this, 'clear_attempts'], 10, 2);
        add_filter('authenticate', [$this, 'check_login_attempts'], 20, 3);
    }

    /**
     * Track a failed login attempt for the current IP.
     *
     * @param string $username Attempted username.
     * @return void
     */
    public function track_failed_login($username) {
        $options = securelywp_get_login_security_options();
        if (empty($options['enabled'])) {
            return;
        }

        $ip = securelywp_get_client_ip();
        SecurelyWP_Rate_Limiter::increment_attempts($ip);
    }

    /**
     * Clear the failed-login counter on successful login.
     *
     * @param string $user_login Username.
     * @param WP_User $user User object.
     * @return void
     */
    public function clear_attempts($user_login, $user) {
        $ip = securelywp_get_client_ip();
        SecurelyWP_Rate_Limiter::clear_attempts($ip);
    }

    /**
     * Block the login if the IP is over the allowed threshold.
     *
     * @param WP_User|WP_Error|null $user User or error object.
     * @param string $username Username.
     * @param string $password Password.
     * @return WP_User|WP_Error|null
     */
    public function check_login_attempts($user, $username, $password) {
        $options = securelywp_get_login_security_options();
        if (empty($options['enabled'])) {
            return $user;
        }

        $ip = securelywp_get_client_ip();
        $attempts = SecurelyWP_Rate_Limiter::get_attempts($ip);

        if ($attempts >= min(absint($options['max_attempts']), SecurelyWP_Rate_Limiter::MAX_ATTEMPTS)) {
            securelywp_record_login_lockout($ip, $attempts);
            return new WP_Error('securelywp_login_lockout', $options['lockout_message']);
        }

        return $user;
    }
}

new SecurelyWP_Login_Security();
