<?php
/**
 * SecurelyWP Prevent User Enumeration
 *
 * Blocks user enumeration attempts via ?author= queries.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Prevent_User_Enum
 *
 * Prevents user enumeration via author queries.
 */
class SecurelyWP_Prevent_User_Enum {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['prevent_user_enum'])) {
            add_action('template_redirect', [$this, 'block_author_queries']);
        }
    }

    /**
     * Block author query enumeration.
     *
     * @return void
     */
    public function block_author_queries() {
        if (is_author() || (isset($_GET['author']) && !empty(sanitize_text_field(wp_unslash($_GET['author']))))) {
            wp_die(esc_html__('Forbidden', 'securelywp'), 403);
        }
    }
}

// Initialize the class
new SecurelyWP_Prevent_User_Enum();