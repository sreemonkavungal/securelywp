<?php
/**
 * SecurelyWP Detect Admin Username
 *
 * Detects if an "admin" username exists and displays a warning.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Detect_Admin_Username
 *
 * Checks for "admin" username and displays a warning notice.
 */
class SecurelyWP_Detect_Admin_Username {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['detect_admin_username'])) {
            add_action('admin_notices', [$this, 'check_admin_username']);
        }
    }

    /**
     * Check for "admin" username and display notice.
     *
     * @return void
     */
    public function check_admin_username() {
        global $wpdb;
        $admin_user = $wpdb->get_var($wpdb->prepare(
            "SELECT user_login FROM $wpdb->users WHERE user_login = %s",
            'admin'
        ));

        if ($admin_user) {
            ?>
            <div class="notice notice-error">
                <p><?php esc_html_e('Security Warning: An "admin" username was detected. This is a common target for brute-force attacks. Please change it to a unique username.', 'securelywp'); ?></p>
                <p><a href="<?php echo esc_url(admin_url('users.php')); ?>" class="button"><?php esc_html_e('Manage Users', 'securelywp'); ?></a></p>
            </div>
            <?php
        }
    }
}

// Initialize the class
new SecurelyWP_Detect_Admin_Username();