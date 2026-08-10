<?php
/**
 * SecurelyWP Cache Purger
 *
 * @package SecurelyWP
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecurelyWP_Cache_Purger {

    private $cache_version_key = 'securelywp_cache_version';

    public function __construct() {
        add_action('admin_bar_menu', [$this, 'add_purge_cache_button'], 100);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('wp_ajax_securelywp_purge_cache', [$this, 'ajax_purge_cache']);
        add_action('admin_notices', [$this, 'show_purge_notice']);
    }

    public function add_purge_cache_button($wp_admin_bar) {
        if (!current_user_can('manage_options')) {
            return;
        }

        $wp_admin_bar->add_node([
            'id'    => 'securelywp-purge-cache',
            'title' => esc_html__('Purge Cache', 'securelywp'),
            'parent'=> 'top-secondary',
            'href'  => '#',
            'meta'  => [
                'class'   => 'securelywp-purge-cache-btn',
                'onclick' => 'securelywpPurgeCache(); return false;',
            ],
        ]);
    }

    public function enqueue_scripts() {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_enqueue_script('jquery');
        wp_add_inline_script('jquery', '
            function securelywpPurgeCache() {
                if (!confirm("' . esc_js(__('Are you sure you want to purge SecurelyWP and plugin caches?', 'securelywp')) . '")) {
                    return;
                }

                jQuery.ajax({
                    url: ajaxurl,
                    type: "POST",
                    data: {
                        action: "securelywp_purge_cache",
                        nonce: "' . wp_create_nonce('securelywp_purge_cache_nonce') . '"
                    },
                    success: function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert("' . esc_js(__('Cache purge failed:', 'securelywp')) . ' " + (response.data || "' . esc_js(__('Unknown error', 'securelywp')) . '"));
                        }
                    },
                    error: function() {
                        alert("' . esc_js(__('Cache purge failed due to network error.', 'securelywp')) . '");
                    }
                });
            }
        ');
    }

    public function ajax_purge_cache() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Insufficient permissions', 'securelywp'));
        }

        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'securelywp_purge_cache_nonce')) {
            wp_die(esc_html__('Security check failed', 'securelywp'));
        }

        $this->purge_all_caches();
        set_transient('securelywp_cache_purged', time(), 30);
        wp_send_json_success(__('Cache purged successfully', 'securelywp'));
    }

    private function purge_all_caches() {
        wp_cache_flush();

        if (function_exists('wp_cache_init')) {
            wp_cache_init();
        }

        $this->purge_plugin_transients();
        delete_expired_transients(true);

        if (function_exists('opcache_reset')) {
            opcache_reset();
        }

        $this->purge_plugin_caches();
        update_option($this->cache_version_key, time(), false);
    }

    private function purge_plugin_transients() {
        global $wpdb;

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
                $wpdb->esc_like('_transient_securelywp_') . '%',
                $wpdb->esc_like('_transient_timeout_securelywp_') . '%'
            )
        );

        if (is_multisite()) {
            $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
                    $wpdb->esc_like('_site_transient_securelywp_') . '%',
                    $wpdb->esc_like('_site_transient_timeout_securelywp_') . '%'
                )
            );
        }
    }

    private function purge_plugin_caches() {
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
        }
        if (class_exists('LiteSpeed_Cache')) {
            LiteSpeed_Cache::get_instance()->purge_all();
        }
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
        }
        if (class_exists('WpFastestCache')) {
            $wpfc = new WpFastestCache();
            $wpfc->deleteCache();
        }
        if (class_exists('Cache_Enabler')) {
            Cache_Enabler::clear_cache();
        }
        if (class_exists('autoptimizeCache')) {
            autoptimizeCache::clearall();
        }
        if (class_exists('WP_Hummingbird')) {
            WP_Hummingbird::flush_cache();
        }
        if (class_exists('Swift_Performance_Cache')) {
            Swift_Performance_Cache::clear_all_cache();
        }
        if (class_exists('comet_cache')) {
            comet_cache::clear();
        }
        if (function_exists('hyper_cache_clear')) {
            hyper_cache_clear();
        }
    }

    public function show_purge_notice() {
        if (get_transient('securelywp_cache_purged')) {
            delete_transient('securelywp_cache_purged');
            ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e('SecurelyWP cache layers have been purged successfully.', 'securelywp'); ?></p>
            </div>
            <?php
        }
    }
}

new SecurelyWP_Cache_Purger();
