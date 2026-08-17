<?php
/**
 * SecurelyWP Rate Limiter
 *
 * Provides object cache-backed rate limiting with a fallback to site transients.
 *
 * @package SecurelyWP
 * @since 1.2.3
 */

if (!defined('ABSPATH')) {
    exit;
}

class SecurelyWP_Rate_Limiter {
    public const CACHE_GROUP = 'securelywp';
    public const KEY_PREFIX = 'securelywp_rate_limit_';
    public const MAX_ATTEMPTS = 5;
    public const WINDOW_SECONDS = 900; // 15 minutes

    /**
     * Get the storage key for the IP.
     *
     * @param string $ip IP address.
     * @return string
     */
    private static function get_key($ip) {
        return self::KEY_PREFIX . md5($ip);
    }

    /**
     * Whether persistent object cache is available.
     *
     * @return bool
     */
    private static function has_object_cache() {
        return function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache();
    }

    /**
     * Get the current attempt count for an IP.
     *
     * @param string $ip IP address.
     * @return int
     */
    public static function get_attempts($ip) {
        $key = self::get_key($ip);

        if (self::has_object_cache()) {
            return (int) wp_cache_get($key, self::CACHE_GROUP);
        }

        return (int) get_site_transient($key);
    }

    /**
     * Increment attempts and persist the counter with the window TTL.
     *
     * @param string $ip IP address.
     * @return int
     */
    public static function increment_attempts($ip) {
        $key = self::get_key($ip);
        $attempts = self::get_attempts($ip) + 1;

        if (self::has_object_cache()) {
            wp_cache_set($key, $attempts, self::CACHE_GROUP, self::WINDOW_SECONDS);
            return $attempts;
        }

        set_site_transient($key, $attempts, self::WINDOW_SECONDS);
        return $attempts;
    }

    /**
     * Delete the stored attempts for an IP.
     *
     * @param string $ip IP address.
     * @return bool
     */
    public static function clear_attempts($ip) {
        $key = self::get_key($ip);

        if (self::has_object_cache()) {
            return wp_cache_delete($key, self::CACHE_GROUP);
        }

        return delete_site_transient($key);
    }

    /**
     * Whether the IP is currently locked out.
     *
     * @param string $ip IP address.
     * @return bool
     */
    public static function is_locked_out($ip) {
        return self::get_attempts($ip) >= self::MAX_ATTEMPTS;
    }
}
