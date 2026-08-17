<?php
/**
 * SecurelyWP shared helpers.
 *
 * @package SecurelyWP
 * @since 1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Get the client IP address.
 *
 * @return string
 */
function securelywp_get_client_ip() {
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR',
    ];

    foreach ($headers as $header) {
        if (empty($_SERVER[$header])) {
            continue;
        }

        $value = sanitize_text_field(wp_unslash($_SERVER[$header]));
        if ($header === 'HTTP_X_FORWARDED_FOR') {
            $parts = explode(',', $value);
            $value = trim($parts[0]);
        }

        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return $value;
        }
    }

    return '0.0.0.0';
}

/**
 * Get the 2FA pending-login cookie token.
 *
 * @return string
 */
function securelywp_2fa_state_key() {
    if (empty($_COOKIE['securelywp_2fa'])) {
        return '';
    }

    return sanitize_key(wp_unslash($_COOKIE['securelywp_2fa']));
}

/**
 * Mark a user as pending 2FA verification during login.
 *
 * @param int $user_id User ID.
 * @return string State token.
 */
function securelywp_2fa_set_pending_user($user_id) {
    $token = wp_generate_password(32, false);
    set_transient('securelywp_2fa_' . $token, absint($user_id), 5 * MINUTE_IN_SECONDS);

    if (!headers_sent()) {
        setcookie(
            'securelywp_2fa',
            $token,
            [
                'expires'  => time() + 5 * MINUTE_IN_SECONDS,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    $_COOKIE['securelywp_2fa'] = $token;

    return $token;
}

/**
 * Get the user ID awaiting 2FA verification.
 *
 * @return int
 */
function securelywp_2fa_get_pending_user_id() {
    $token = securelywp_2fa_state_key();
    if ($token === '') {
        return 0;
    }

    return absint(get_transient('securelywp_2fa_' . $token));
}

/**
 * Clear pending 2FA login state.
 *
 * @return void
 */
function securelywp_2fa_clear_pending_user() {
    $token = securelywp_2fa_state_key();
    if ($token !== '') {
        delete_transient('securelywp_2fa_' . $token);
    }

    if (!headers_sent()) {
        setcookie(
            'securelywp_2fa',
            '',
            [
                'expires'  => time() - HOUR_IN_SECONDS,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    unset($_COOKIE['securelywp_2fa']);
}

/**
 * Determine whether a user has 2FA enabled.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function securelywp_user_has_2fa_enabled($user_id) {
    $options = get_user_meta($user_id, 'securelywp_2fa_user_options', true);
    if (!is_array($options)) {
        return false;
    }

    if (!empty($options['enable_email_2fa'])) {
        return true;
    }

    if (!empty($options['enable_recovery_codes']) && !empty($options['recovery_codes'])) {
        return true;
    }

    return !empty($options['enable_totp']) && !empty($options['totp_verified']) && !empty($options['totp_secret']);
}

/**
 * Count users with 2FA enabled.
 *
 * @return int
 */
function securelywp_count_users_with_2fa() {
    $users = get_users(['fields' => 'ID']);
    $count = 0;

    foreach ($users as $user_id) {
        if (securelywp_user_has_2fa_enabled($user_id)) {
            $count++;
        }
    }

    return $count;
}

/**
 * Get login security settings.
 *
 * @return array{enabled:bool,max_attempts:int,lockout_duration:int,lockout_message:string}
 */
function securelywp_get_login_security_options() {
    $defaults = [
        'enabled'          => true,
        'max_attempts'     => 5,
        'lockout_duration' => 5,
        'lockout_message'  => __('Too many failed login attempts. Please try again later.', 'securelywp'),
    ];

    $saved = get_option('securelywp_login_security_options', []);
    if (!is_array($saved)) {
        $saved = [];
    }

    $options = wp_parse_args($saved, $defaults);
    $options['enabled'] = !empty($options['enabled']);
    $options['max_attempts'] = max(1, absint($options['max_attempts']));
    $options['lockout_duration'] = max(1, absint($options['lockout_duration']));
    $options['lockout_message'] = sanitize_text_field((string) ($options['lockout_message'] ?? $defaults['lockout_message']));

    return $options;
}

/**
 * Record a lockout event for the current IP.
 *
 * @param string $ip Client IP.
 * @param int $attempts Attempt count.
 * @return void
 */
function securelywp_record_login_lockout($ip, $attempts) {
    $events = get_option('securelywp_login_lockout_events', []);
    if (!is_array($events)) {
        $events = [];
    }

    $events[] = [
        'ip' => sanitize_text_field($ip),
        'attempts' => max(1, absint($attempts)),
        'time' => current_time('timestamp'),
    ];

    if (count($events) > 20) {
        $events = array_slice($events, -20);
    }

    update_option('securelywp_login_lockout_events', $events);
}

/**
 * Generate static security header rules for Apache/LiteSpeed and Nginx.
 *
 * @return array<string,string>
 */
function securelywp_get_static_header_rules() {
    $headers = get_option('securelywp_headers_options', []);

    $x_frame_options = !empty($headers['x_frame_options_active']) ? strtoupper(sanitize_text_field($headers['x_frame_options'])) : 'SAMEORIGIN';
    $x_content_type_options = !empty($headers['x_content_type_options_active']) ? 'nosniff' : '';
    $referrer_policy = !empty($headers['referrer_policy_active']) ? sanitize_text_field($headers['referrer_policy']) : 'strict-origin-when-cross-origin';

    $hsts = '';
    if (!empty($headers['hsts_active']) && is_ssl()) {
        $max_age = absint($headers['hsts_max_age']);
        $max_age = $max_age < 31536000 ? 31536000 : $max_age;
        $hsts = 'max-age=' . $max_age;
        if (!empty($headers['hsts_include_subdomains'])) {
            $hsts .= '; includeSubDomains';
        }
        if (!empty($headers['hsts_preload'])) {
            $hsts .= '; preload';
        }
    }

    $apache_headers = [];
    $nginx_headers = [];

    if ($x_frame_options) {
        $apache_headers[] = sprintf('Header always set X-Frame-Options "%s"', esc_attr($x_frame_options));
        $nginx_headers[] = sprintf('add_header X-Frame-Options "%s" always;', esc_attr($x_frame_options));
    }
    if ($x_content_type_options) {
        $apache_headers[] = 'Header always set X-Content-Type-Options "nosniff"';
        $nginx_headers[] = 'add_header X-Content-Type-Options "nosniff" always;';
    }
    if ($referrer_policy) {
        $apache_headers[] = sprintf('Header always set Referrer-Policy "%s"', esc_attr($referrer_policy));
        $nginx_headers[] = sprintf('add_header Referrer-Policy "%s" always;', esc_attr($referrer_policy));
    }
    if ($hsts) {
        $apache_headers[] = sprintf('Header always set Strict-Transport-Security "%s"', esc_attr($hsts));
        $nginx_headers[] = sprintf('add_header Strict-Transport-Security "%s" always;', esc_attr($hsts));
    }

    return [
        'apache' => implode("\n", $apache_headers),
        'nginx' => implode("\n", $nginx_headers),
    ];
}

/**
 * Get recent login lockout events.
 *
 * @return array<int,array{ip:string,attempts:int,time:int}>
 */
function securelywp_get_login_lockout_events() {
    $events = get_option('securelywp_login_lockout_events', []);
    if (!is_array($events)) {
        return [];
    }

    usort($events, static function ($a, $b) {
        return ($b['time'] ?? 0) <=> ($a['time'] ?? 0);
    });

    return array_slice($events, 0, 10);
}

/**
 * Summarize vulnerability scan results for the dashboard.
 *
 * @return array{count:int,timestamp:string,scanning:bool}
 */
function securelywp_get_vulnerability_summary() {
    $results = get_transient('securelywp_vulnerability_data');
    $summary = [
        'count'     => 0,
        'timestamp' => '',
        'scanning'  => (bool) get_transient('securelywp_vulnerability_scan_running'),
    ];

    if (!is_array($results)) {
        return $summary;
    }

    $summary['timestamp'] = isset($results['timestamp']) ? (string) $results['timestamp'] : '';

    foreach (['plugins', 'themes'] as $type) {
        if (empty($results[$type]) || !is_array($results[$type])) {
            continue;
        }

        foreach ($results[$type] as $item) {
            if (!empty($item['status']['vulnerable']) || !empty($item['status']['abandoned'])) {
                $summary['count']++;
            }
        }
    }

    return $summary;
}

/**
 * Resolve the 2FA method for a user.
 *
 * @param array $user_2fa_options User 2FA options.
 * @return string
 */
function securelywp_2fa_resolve_method($user_2fa_options) {
    $method = $user_2fa_options['primary_2fa_method'] ?? 'totp';

    if ($method === 'totp' && (empty($user_2fa_options['enable_totp']) || empty($user_2fa_options['totp_verified']) || empty($user_2fa_options['totp_secret']))) {
        $method = !empty($user_2fa_options['enable_email_2fa']) ? 'email' : (!empty($user_2fa_options['enable_recovery_codes']) ? 'backup_codes' : 'none');
    } elseif ($method === 'email' && empty($user_2fa_options['enable_email_2fa'])) {
        $method = (!empty($user_2fa_options['enable_totp']) && !empty($user_2fa_options['totp_verified'])) ? 'totp' : (!empty($user_2fa_options['enable_recovery_codes']) ? 'backup_codes' : 'none');
    } elseif ($method === 'backup_codes' && empty($user_2fa_options['enable_recovery_codes'])) {
        $method = (!empty($user_2fa_options['enable_totp']) && !empty($user_2fa_options['totp_verified'])) ? 'totp' : (!empty($user_2fa_options['enable_email_2fa']) ? 'email' : 'none');
    }

    return $method;
}

/**
 * Determine whether 2FA is required for a user.
 *
 * @param array $user_2fa_options User 2FA options.
 * @return bool
 */
function securelywp_2fa_is_required($user_2fa_options) {
    $global_2fa_options = get_option('securelywp_2fa_options', []);
    $enforce_2fa = is_multisite() && !empty($global_2fa_options['enforce_2fa_network']);

    return $enforce_2fa
        || securelywp_user_has_2fa_enabled_from_options($user_2fa_options);
}

/**
 * Determine whether 2FA options indicate an enabled method.
 *
 * @param array $user_2fa_options User 2FA options.
 * @return bool
 */
function securelywp_user_has_2fa_enabled_from_options($user_2fa_options) {
    if (!is_array($user_2fa_options)) {
        return false;
    }

    if (!empty($user_2fa_options['enable_email_2fa'])) {
        return true;
    }

    if (!empty($user_2fa_options['enable_recovery_codes']) && !empty($user_2fa_options['recovery_codes'])) {
        return true;
    }

    return !empty($user_2fa_options['enable_totp'])
        && !empty($user_2fa_options['totp_verified'])
        && !empty($user_2fa_options['totp_secret']);
}
