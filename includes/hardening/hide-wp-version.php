<?php
/**
 * SecurelyWP Hide WordPress Version
 *
 * Removes WordPress version from meta tags, scripts, and styles to prevent version-specific exploits.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Hide_WP_Version
 *
 * Handles hiding WordPress version information.
 */
class SecurelyWP_Hide_WP_Version {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['hide_wp_version'])) {
            $this->hide_version();
        }
    }

    /**
     * Hide WordPress version from meta tags, scripts, and styles.
     *
     * @return void
     */
    private function hide_version() {
        // Remove generator meta tag
        remove_action('wp_head', 'wp_generator');

        // Remove version from scripts and styles
        add_filter('style_loader_src', [$this, 'remove_version_query'], 9999);
        add_filter('script_loader_src', [$this, 'remove_version_query'], 9999);
    }

    /**
     * Remove version query string from scripts and styles.
     *
     * @param string $src The source URL.
     * @return string Modified URL.
     */
    public function remove_version_query($src) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return esc_url_raw($src);
    }
}

// Initialize the class
new SecurelyWP_Hide_WP_Version();