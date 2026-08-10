<?php
/**
 * SecurelyWP Brute Force Protection (Lite)
 *
 * Limits login attempts per IP to prevent brute force attacks.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Brute_Force_Lite
 *
 * Implements basic brute force protection.
 */
class SecurelyWP_Brute_Force_Lite {
    /**
     * Maximum allowed login attempts.
     *
     * @var int
     */
    private $max_attempts = 5;

    /**
     * Lockout duration in seconds (5 minutes).
     *
     * @var int
     */
    private $lockout_duration = 300;

    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['brute_force_protection'])) {
            add_action('wp_login_failed', [$this, 'track_failed_login']);
            add_action('wp_login', [$this, 'clear_attempts'], 10, 2);
            add_filter('authenticate', [$this, 'check_login_attempts'], 20, 3);
        }
    }

    /**
     * Track failed login attempts.
     *
     * @param string $username Attempted username.
     * @return void
     */
    public function track_failed_login($username) {
        $ip = securelywp_get_client_ip();
        $transient_key = 'securelywp_login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key) ?: 0;
        $attempts++;
        set_transient($transient_key, $attempts, $this->lockout_duration);
    }

    /**
     * Clear attempts on successful login.
     *
     * @param string $user_login Username.
     * @param WP_User $user User object.
     * @return void
     */
    public function clear_attempts($user_login, $user) {
        $ip = securelywp_get_client_ip();
        $transient_key = 'securelywp_login_attempts_' . md5($ip);
        delete_transient($transient_key);
    }

    /**
     * Check if login attempts exceed limit.
     *
     * @param WP_User|WP_Error|null $user User or error object.
     * @param string $username Username.
     * @param string $password Password.
     * @return WP_User|WP_Error
     */
    public function check_login_attempts($user, $username, $password) {
        $ip = securelywp_get_client_ip();
        $transient_key = 'securelywp_login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key) ?: 0;

        if ($attempts >= $this->max_attempts) {
            return new WP_Error('too_many_attempts', esc_html__('Too many login attempts. Please try again later.', 'securelywp'));
        }

        return $user;
    }
}

// Initialize the class
new SecurelyWP_Brute_Force_Lite();