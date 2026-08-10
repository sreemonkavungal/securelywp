<?php
/**
 * SecurelyWP Disable Emojis
 *
 * Removes emoji scripts and styles for faster page loads.
 *
 * @package SecurelyWP
 * @since 1.2.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Disable_Emojis
 */
class SecurelyWP_Disable_Emojis {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);

        if (!empty($options['disable_emojis'])) {
            add_action('init', [$this, 'disable_emojis']);
            add_filter('tiny_mce_plugins', [$this, 'disable_emojis_tinymce']);
            add_filter('wp_resource_hints', [$this, 'remove_emoji_svg_url'], 10, 2);
        }
    }

    /**
     * Disable emoji support scripts and styles.
     *
     * @return void
     */
    public function disable_emojis() {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');
    }

    /**
     * Remove emoji plugin from TinyMCE.
     *
     * @param array|null $plugins TinyMCE plugins.
     * @return array|null
     */
    public function disable_emojis_tinymce($plugins) {
        if (is_array($plugins)) {
            return array_diff($plugins, ['wpemoji']);
        }

        return $plugins;
    }

    /**
     * Remove emoji CDN from resource hints.
     *
     * @param array  $urls URLs.
     * @param string $relation_type Relation type.
     * @return array
     */
    public function remove_emoji_svg_url($urls, $relation_type) {
        if ('dns-prefetch' === $relation_type) {
            $emoji_url = 'https://s.w.org';
            $key = array_search($emoji_url, $urls, true);
            if ($key !== false) {
                unset($urls[$key]);
            }
        }

        return $urls;
    }
}

new SecurelyWP_Disable_Emojis();