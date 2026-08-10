<?php
/**
 * SecurelyWP Disable File Editing
 *
 * Disables theme and plugin file editing in the WordPress dashboard.
 *
 * @package SecurelyWP
 * @since 1.0.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Disable_File_Edit
 *
 * Defines constant to disable file editing.
 */
class SecurelyWP_Disable_File_Edit {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);
        if (!empty($options['disable_file_edit']) && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
    }
}

// Initialize the class
new SecurelyWP_Disable_File_Edit();