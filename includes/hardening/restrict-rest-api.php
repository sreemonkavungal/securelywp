<?php
/**
 * SecurelyWP Restrict REST API
 *
 * Limits REST API access to authenticated users only.
 *
 * @package SecurelyWP
 * @since 1.2.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Restrict_REST_API
 */
class SecurelyWP_Restrict_REST_API {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);

        if (!empty($options['restrict_rest_api'])) {
            add_filter('rest_authentication_errors', [$this, 'restrict_rest_api'], 99);
        }
    }

    /**
     * Restrict REST API to authenticated users.
     *
     * @param WP_Error|null|true $result Current authorization result.
     * @return WP_Error|null|true
     */
    public function restrict_rest_api($result) {
        if (!empty($result) || is_user_logged_in()) {
            return $result;
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            return new WP_Error(
                'securelywp_rest_forbidden',
                esc_html__('REST API access is restricted to authenticated users.', 'securelywp'),
                ['status' => 403]
            );
        }

        return $result;
    }
}

new SecurelyWP_Restrict_REST_API();