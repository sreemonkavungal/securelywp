<?php
/**
 * SecurelyWP Disable PHP Execution in Uploads
 *
 * Prevents PHP execution in the uploads directory.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecurelyWP_Disable_PHP_Uploads {
    private $uploads_dir;

    public function __construct() {
        $this->uploads_dir = wp_normalize_path(wp_upload_dir()['basedir']);
        add_action('init', [$this, 'initialize']);
        register_deactivation_hook(SECURELYWP_PATH . 'securelywp.php', [$this, 'cleanup']);
    }

    public function initialize() {
        if (get_option('securelywp_hardening_options')['disable_php_uploads'] ?? false) {
            $this->disable_php_execution();
        }
    }

    private function disable_php_execution() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        $htaccess_file = $this->uploads_dir . '/.htaccess';
        $content = "<IfModule mod_php.c>\nphp_flag engine off\n</IfModule>";

        if ($this->initialize_filesystem()) {
            global $wp_filesystem;
            $wp_filesystem->put_contents($htaccess_file, $content, 0644);
        }
    }

    public function cleanup() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        $htaccess_file = $this->uploads_dir . '/.htaccess';

        if ($this->initialize_filesystem()) {
            global $wp_filesystem;
            if ($wp_filesystem->exists($htaccess_file)) {
                $wp_filesystem->delete($htaccess_file);
            }
        }
    }

    private function initialize_filesystem() {
        global $wp_filesystem;

        if (isset($wp_filesystem) && is_a($wp_filesystem, 'WP_Filesystem_Base')) {
            return true;
        }

        $url = wp_nonce_url('plugins.php?action=deactivate&plugin=' . plugin_basename(SECURELYWP_PATH . 'securelywp.php'), 'deactivate-plugin_' . plugin_basename(SECURELYWP_PATH . 'securelywp.php'));
        $creds = request_filesystem_credentials($url, '', false, false, null);

        if (false === $creds || !WP_Filesystem($creds)) {
            return false;
        }

        return true;
    }
}

new SecurelyWP_Disable_PHP_Uploads();