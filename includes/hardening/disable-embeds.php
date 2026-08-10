<?php
/**
 * SecurelyWP Disable Embeds
 *
 * Disables oEmbed discovery and embeds to reduce load and attack surface.
 *
 * @package SecurelyWP
 * @since 1.2.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Disable_Embeds
 */
class SecurelyWP_Disable_Embeds {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);

        if (!empty($options['disable_embeds'])) {
            add_action('init', [$this, 'disable_embeds']);
            add_filter('tiny_mce_plugins', [$this, 'disable_embeds_tinymce']);
            add_filter('rest_enabled', '__return_false');
            add_filter('rest_jsonp_enabled', '__return_false');
        }
    }

    /**
     * Disable embed discovery and routes.
     *
     * @return void
     */
    public function disable_embeds() {
        remove_action('rest_api_init', 'wp_oembed_register_route');
        remove_filter('oembed_dataparse', 'wp_filter_oembed_result', 10);
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
        remove_action('wp_head', 'wp_oembed_add_host_js');
        add_filter('embed_oembed_discover', '__return_false');
    }

    /**
     * Remove wpembed from TinyMCE plugins.
     *
     * @param array|null $plugins TinyMCE plugins.
     * @return array|null
     */
    public function disable_embeds_tinymce($plugins) {
        if (is_array($plugins)) {
            return array_diff($plugins, ['wpembed']);
        }

        return $plugins;
    }
}

new SecurelyWP_Disable_Embeds();