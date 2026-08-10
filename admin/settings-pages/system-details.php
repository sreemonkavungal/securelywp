<?php
/**
 * SecurelyWP System Details Page
 *
 * @package SecurelyWP
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Count files in a directory recursively.
 *
 * @param string $directory Directory path.
 * @return int
 */
function securelywp_count_files_in_directory($directory) {
    if (!is_dir($directory)) {
        return 0;
    }

    $count = 0;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $count++;
        }
    }

    return $count;
}

/**
 * Build system details payload.
 *
 * @return array
 */
function securelywp_build_system_details() {
    global $wpdb;

    $site_url = esc_url_raw(site_url());
    $wp_url = esc_url_raw(home_url());
    $wp_install_dir = wp_normalize_path(ABSPATH);
    $wp_version = get_bloginfo('version');
    $wp_language = get_locale();
    $is_multisite = is_multisite() ? 'Yes' : 'No';
    $active_theme = esc_url_raw(get_template_directory_uri());
    $parent_theme = wp_get_theme()->parent() ? esc_url_raw(get_template_directory_uri()) : $active_theme;
    $user_roles = array_keys($GLOBALS['wp_roles']->roles);
    $user_roles = !empty($user_roles) ? implode(', ', $user_roles) : 'None';
    $mu_plugins = array_keys(get_mu_plugins());
    $mu_plugins = !empty($mu_plugins) ? implode(', ', $mu_plugins) : 'None';
    $php_version = phpversion();
    $web_server = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : 'Unknown';
    $server_os = php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m');
    $server_address = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : 'Unknown';
    $server_port = isset($_SERVER['SERVER_PORT']) ? absint($_SERVER['SERVER_PORT']) : 'Unknown';

    $dirs = [
        wp_normalize_path(ABSPATH . 'blog/'),
        wp_normalize_path(ABSPATH . 'wp-admin/'),
        wp_normalize_path(ABSPATH . 'wp-content/'),
        wp_normalize_path(ABSPATH . 'wp-content/plugins/'),
        wp_normalize_path(ABSPATH . 'wp-content/uploads/'),
        wp_normalize_path(ABSPATH . 'wp-includes/'),
    ];

    $dir_counts = [];
    $total_files = 0;
    foreach ($dirs as $dir) {
        $count = securelywp_count_files_in_directory($dir);
        if ($count > 0) {
            $dir_counts[$dir] = $count;
            $total_files += $count;
        }
    }

    $hidden_files = [];
    $root_files = scandir(ABSPATH);
    foreach ($root_files as $file) {
        if (strpos($file, '.') === 0 && is_file(ABSPATH . $file)) {
            $hidden_files[] = '[FILE] ' . wp_normalize_path(ABSPATH . $file);
        }
    }

    $sub_dirs = [
        wp_normalize_path(ABSPATH . 'wp-content/'),
        wp_normalize_path(ABSPATH . 'blog/'),
        wp_normalize_path(ABSPATH . 'wp-content/plugins/'),
    ];
    foreach ($sub_dirs as $dir) {
        if (!is_dir($dir)) {
            continue;
        }
        $sub_files = scandir($dir);
        foreach ($sub_files as $file) {
            if (in_array($file, ['.htaccess', '.gitignore'], true) && is_file($dir . $file)) {
                $hidden_files[] = '[FILE] ' . wp_normalize_path($dir . $file);
            }
        }
    }

    $logged_in_users = [];
    $current_user = wp_get_current_user();
    $sessions = WP_Session_Tokens::get_instance(get_current_user_id())->get_all();
    foreach ($sessions as $session) {
        $logged_in_users[] = [
            'ip'         => sanitize_text_field($session['ip']),
            'ua'         => sanitize_text_field($session['ua']),
            'start'      => gmdate('c', absint($session['login'])),
            'expiration' => gmdate('c', absint($session['expiration'])),
        ];
    }

    $current_user_data = [
        'ID'              => $current_user->ID,
        'roles'           => $current_user->roles,
        'user_login'      => $current_user->user_login,
        'user_email'      => $current_user->user_email,
        'display_name'    => $current_user->display_name,
        'user_registered' => $current_user->user_registered,
    ];

    return compact(
        'site_url',
        'wp_url',
        'wp_install_dir',
        'wp_version',
        'wp_language',
        'is_multisite',
        'active_theme',
        'parent_theme',
        'user_roles',
        'mu_plugins',
        'php_version',
        'web_server',
        'server_os',
        'server_address',
        'server_port',
        'total_files',
        'dir_counts',
        'hidden_files',
        'logged_in_users',
        'current_user_data'
    );
}

function securelywp_system_details_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'securelywp'));
    }

    if (isset($_GET['refresh_system_details']) && check_admin_referer('securelywp_refresh_system_details')) {
        delete_transient('securelywp_system_details_cache');
    }

    $details = get_transient('securelywp_system_details_cache');
    if (!is_array($details)) {
        $details = securelywp_build_system_details();
        set_transient('securelywp_system_details_cache', $details, HOUR_IN_SECONDS);
    }

    extract($details, EXTR_SKIP);
    ?>
    <div class="wrap securelywp-dashboard securelywp-system-details">
        <h1><?php esc_html_e('System Details', 'securelywp'); ?></h1>
        <p>
            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg('refresh_system_details', '1'), 'securelywp_refresh_system_details')); ?>" class="button button-secondary">
                <?php esc_html_e('Refresh Data', 'securelywp'); ?>
            </a>
        </p>

        <div class="securelywp-card">
            <h2><?php esc_html_e('System Details', 'securelywp'); ?></h2>
            <table class="wp-list-table widefat fixed">
                <tbody>
                    <tr><th><?php esc_html_e('Website URL', 'securelywp'); ?></th><td><?php echo esc_html($site_url); ?></td></tr>
                    <tr><th><?php esc_html_e('WP URL', 'securelywp'); ?></th><td><?php echo esc_html($wp_url); ?></td></tr>
                    <tr><th><?php esc_html_e('WP Installation DIR', 'securelywp'); ?></th><td><?php echo esc_html($wp_install_dir); ?></td></tr>
                    <tr><th><?php esc_html_e('WP Version', 'securelywp'); ?></th><td><?php echo esc_html($wp_version); ?></td></tr>
                    <tr><th><?php esc_html_e('WP Language', 'securelywp'); ?></th><td><?php echo esc_html($wp_language); ?></td></tr>
                    <tr><th><?php esc_html_e('WP Multisite', 'securelywp'); ?></th><td><?php echo esc_html($is_multisite); ?></td></tr>
                    <tr><th><?php esc_html_e('Active Theme', 'securelywp'); ?></th><td><?php echo esc_html($active_theme); ?></td></tr>
                    <tr><th><?php esc_html_e('Parent Theme', 'securelywp'); ?></th><td><?php echo esc_html($parent_theme); ?></td></tr>
                    <tr><th><?php esc_html_e('User Roles', 'securelywp'); ?></th><td><?php echo esc_html($user_roles); ?></td></tr>
                    <tr><th><?php esc_html_e('Must-Use Plugins', 'securelywp'); ?></th><td><?php echo esc_html($mu_plugins); ?></td></tr>
                    <tr><th><?php esc_html_e('PHP Version', 'securelywp'); ?></th><td><?php echo esc_html($php_version); ?></td></tr>
                    <tr><th><?php esc_html_e('Web Server', 'securelywp'); ?></th><td><?php echo esc_html($web_server); ?></td></tr>
                    <tr><th><?php esc_html_e('Server OS', 'securelywp'); ?></th><td><?php echo esc_html($server_os); ?></td></tr>
                    <tr><th><?php esc_html_e('Server Address', 'securelywp'); ?></th><td><?php echo esc_html($server_address); ?></td></tr>
                    <tr><th><?php esc_html_e('Server Port', 'securelywp'); ?></th><td><?php echo esc_html((string) $server_port); ?></td></tr>
                    <tr><th><?php esc_html_e('Total Files (selected dirs)', 'securelywp'); ?></th><td><?php echo esc_html((string) $total_files); ?></td></tr>
                    <tr><th colspan="2"><?php esc_html_e('Directory File Counts', 'securelywp'); ?></th></tr>
                    <?php foreach ($dir_counts as $dir => $count) : ?>
                        <tr><td><?php echo esc_html($dir); ?></td><td><?php echo esc_html((string) $count); ?></td></tr>
                    <?php endforeach; ?>
                    <tr><th colspan="2"><?php esc_html_e('Hidden Files & Folders', 'securelywp'); ?></th></tr>
                    <?php if (empty($hidden_files)) : ?>
                        <tr><td colspan="2"><?php esc_html_e('None', 'securelywp'); ?></td></tr>
                    <?php else : ?>
                        <?php foreach ($hidden_files as $file) : ?>
                            <tr><td colspan="2"><?php echo esc_html($file); ?></td></tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    <tr><th colspan="2"><?php esc_html_e('Logged-In Users', 'securelywp'); ?></th></tr>
                    <tr><td><?php esc_html_e('User ID', 'securelywp'); ?></td><td><?php echo esc_html((string) $current_user_data['ID']); ?></td></tr>
                    <tr><td><?php esc_html_e('User Roles', 'securelywp'); ?></td><td><?php echo esc_html(implode(', ', $current_user_data['roles'])); ?></td></tr>
                    <tr><td><?php esc_html_e('User Login', 'securelywp'); ?></td><td><?php echo esc_html($current_user_data['user_login']); ?></td></tr>
                    <tr><td><?php esc_html_e('User Email', 'securelywp'); ?></td><td><?php echo esc_html($current_user_data['user_email']); ?></td></tr>
                    <tr><td><?php esc_html_e('Display Name', 'securelywp'); ?></td><td><?php echo esc_html($current_user_data['display_name']); ?></td></tr>
                    <tr><td><?php esc_html_e('Registered', 'securelywp'); ?></td><td><?php echo esc_html($current_user_data['user_registered']); ?></td></tr>
                    <?php if (!empty($logged_in_users)) : ?>
                        <?php foreach ($logged_in_users as $session) : ?>
                            <tr><td><?php esc_html_e('IP Address', 'securelywp'); ?></td><td><?php echo esc_html($session['ip']); ?></td></tr>
                            <tr><td><?php esc_html_e('User-Agent', 'securelywp'); ?></td><td><?php echo esc_html($session['ua']); ?></td></tr>
                            <tr><td><?php esc_html_e('Session Start', 'securelywp'); ?></td><td><?php echo esc_html($session['start']); ?></td></tr>
                            <tr><td><?php esc_html_e('Session Expiration', 'securelywp'); ?></td><td><?php echo esc_html($session['expiration']); ?></td></tr>
                        <?php endforeach; ?>
                    <?php else : ?>
                        <tr><td colspan="2"><?php esc_html_e('No active sessions found.', 'securelywp'); ?></td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php
}
