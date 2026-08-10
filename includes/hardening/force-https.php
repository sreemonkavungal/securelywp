<?php
/**
 * SecurelyWP Force HTTPS
 *
 * Forces HTTPS for login and admin pages to prevent credential theft.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Force_HTTPS
 *
 * Enforces HTTPS for admin and login pages.
 */
class SecurelyWP_Force_HTTPS {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['force_https']) && is_ssl()) {
            $this->force_https();
        }
    }

    /**
     * Force HTTPS for admin and login pages.
     *
     * @return void
     */
    private function force_https() {
        if (!defined('FORCE_SSL_ADMIN')) {
            define('FORCE_SSL_ADMIN', true);
        }
        add_filter('login_url', [$this, 'ensure_https_url'], 10, 3);
        add_filter('admin_url', [$this, 'ensure_https_url'], 10, 3);
    }

    /**
     * Ensure HTTPS in URLs.
     *
     * @param string $url The URL.
     * @return string Modified HTTPS URL.
     */
    public function ensure_https_url($url) {
        return str_replace('http://', 'https://', esc_url_raw($url));
    }
}

// Initialize the class
new SecurelyWP_Force_HTTPS();