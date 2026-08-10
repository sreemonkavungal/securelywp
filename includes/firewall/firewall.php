<?php
/**
 * SecurelyWP Firewall
 *
 * @package SecurelyWP
 * @since 1.0.8
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main firewall function to filter requests
 */
function securelywp_firewall_core() {
    // Check if firewall is enabled
    $options = get_option('securelywp_firewall_options', [
        'enable_firewall' => true,
        'custom_rules' => '',
        'whitelist' => '',
        'check_request_uri' => true,
        'check_query_string' => true,
        'check_user_agent' => true,
        'check_referrer' => true,
        'check_post_body' => true,
        'check_long_requests' => true,
    ]);
    $options = wp_parse_args($options, [
        'enable_firewall' => true,
        'custom_rules' => '',
        'whitelist' => '',
        'check_request_uri' => true,
        'check_query_string' => true,
        'check_user_agent' => true,
        'check_referrer' => true,
        'check_post_body' => true,
        'check_long_requests' => true,
    ]);
    if (empty($options['enable_firewall'])) {
        return;
    }

    // Default patterns
    $request_uri_array = apply_filters('securelywp_request_uri_items', ['\/\.env', '\s', '<', '>', '\^', '`', '@@', ',,,', '\?\?', '\/&&', '\\', '\/=', '\/:\/', '\/\/\/', '\.\.\.', '\/\*(.*)\*\/', '\+\+\+', '------', '\{0\}', '0x00', '%00', '\(\/\(', '(\/|;|=|,)nt\.', '@eval', 'eval\(', 'union(.*)select', '\(null\)', 'base64_', '(\/|%2f)localhost', '(\/|%2f)pingserver', 'wp-config\.php', '(\/|\.)(s?ftp-?)?conf(ig)?(uration)?\.', '\/wwwroot', '\/makefile', 'crossdomain\.', 'self\/environ', 'usr\/bin\/perl', 'var\/lib\/php', 'etc\/passwd', 'etc\/hosts', 'etc\/motd', 'etc\/shadow', '\/https:', '\/http:', '\/ftp:', '\/file:', '\/php:', '\/cgi\/', '\.asp', '\.bak', '\.bash', '\.bat', '\.cfg', '\.cgi', '\.cmd', '\.conf', '\.db', '\.dll', '\.ds_store', '\.exe', '\/\.git', '\.hta', '\.htp', '\.init?', '\.jsp', '\.msi', '\.mysql', '\.pass', '\.pwd', '\.sql', '\/\.svn', '\.exec\(', '\)\.html\(', '\{x\.html\(', '\.php\([0-9]+\)', '\/((.*)header:|(.*)set-cookie:(.*)=)', '(benchmark|sleep)(\s|%20)*\(', '\/(db|mysql)-?admin', '\/document_root', '\/error_log', 'indoxploi', '\/sqlpatch', 'xrumer', 'www\.(.*)\.cn', '%3Cscript', '(\.)(htaccess|htpasswd|mysql-select-db)(\/)?$', '\/(db|master|sql|wp|www|wwwroot)\.(gz|zip)', '\/((boot)?_?admin(er|istrator|s)(_events)?)\.php', '\/(force-download|framework\/main)\.php', '\/(f?ckfinder|fck\/|f?ckeditor|fullclick)', '\/vbforum(\/)?', '\/vbull(etin)?(\/)?', '\{\$itemURL\}', '(\/bin\/)(cc|chmod|chsh|cpp|echo|id|kill|mail|nasm|perl|ping|ps|python|tclsh)(\/)?$', '((curl_|shell_)?exec|(f|p)open|function|fwrite|leak|p?fsockopen|passthru|phpinfo|posix_(kill|mkfifo|setpgid|setsid|setuid)|proc_(close|get_status|nice|open|terminate)|system)(.*)(\()(.*)(\))', '(\/)(^$|0day|c99|configbak|curltest|db|index\.php\/index|(my)?sql|(php|web)?shell|php-?info|temp00|vuln|webconfig)(\.php)']);

    $query_string_array = apply_filters('securelywp_query_string_items', ['\(0x', '0x3c62723e', ';!--=', '\(\)\}', ':;\};', '\.\.\/', '\/\*\*\/', '127\.0\.0\.1', 'localhost', 'loopback', '%0a', '%0d', '%00', '%2e%2e', '%0d%0a', '@copy', 'concat(.*)(\(|%28)', 'allow_url_(fopen|include)', '(c99|php|web)shell', 'auto_prepend_file', 'disable_functions?', 'gethostbyname', 'input_file', 'execute', 'safe_mode', 'file_(get|put)_contents', 'mosconfig', 'open_basedir', 'outfile', 'proc_open', 'root_path', 'user_func_array', 'path=\.', 'mod=\.', '(\/|%2f)(:|%3a)(\/|%2f)', 'etc\/(hosts|motd|shadow)', '(globals|request)(=|\[)', 'order(\s|%20)by(\s|%20)1--', 'f(fclose|fgets|fputs|fsbuff)', '\$_(env|files|get|post|request|server|session)', '(\+|%2b)(concat|delete|get|select|union)(\+|%2b)', '(cmd|command)(=|%3d)(chdir|mkdir)', '(absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?)', '(s)?(ftp|inurl|php)(s)?(:(\/|%2f|%u2215)(\/|%2f|%u2215))', '(\/|%2f)(=|%3d|\$&|_mm|cgi(\.|-)|inurl(:|%3a)(\/|%2f)|(mod|path)(=|%3d)(\.|%2e))', '(<|>|\'|")(.*)(\/\*|alter|base64|benchmark|cast|char|concat|convert|create|declare|delete|drop|encode|exec|fopen|function|html|insert|md5|request|script|select|set|union|update)']);

    $user_agent_array = apply_filters('securelywp_user_agent_items', ['&lt;', '%0a', '%0d', '%27', '%3c', '%3e', '%00', '0x00', '\/bin\/bash', '360Spider', 'acapbot', 'acoonbot', 'alexibot', 'asterias', 'attackbot', 'backdorbot', 'base64_decode', 'becomebot', 'bin\/bash', 'binlar', 'blackwidow', 'blekkobot', 'blexbot', 'blowfish', 'bullseye', 'bunnys', 'butterfly', 'careerbot', 'casper', 'checkpriv', 'cheesebot', 'cherrypick', 'chinaclaw', 'choppy', 'clshttp', 'cmsworld', 'copernic', 'copyrightcheck', 'cosmos', 'crescent', 'cy_cho', 'datacha', 'demon', 'diavol', 'discobot', 'disconnect', 'dittospyder', 'dotbot', 'dotnetdotcom', 'dumbot', 'emailcollector', 'emailsiphon', 'emailwolf', 'eval\(', 'exabot', 'extract', 'eyenetie', 'feedfinder', 'flaming', 'flashget', 'flicky', 'foobot', 'g00g1e', 'getright', 'gigabot', 'go-ahead-got', 'gozilla', 'grabnet', 'grafula', 'harvest', 'heritrix', 'httrack', 'icarus6j', 'jetbot', 'jetcar', 'jikespider', 'kmccrew', 'leechftp', 'libweb', 'linkextractor', 'linkscan', 'linkwalker', 'loader', 'lwp-download', 'masscan', 'miner', 'majestic', 'md5sum', 'mechanize', 'mj12bot', 'morfeus', 'moveoverbot', 'netmechanic', 'netspider', 'nicerspro', 'nikto', 'nutch', 'octopus', 'pagegrabber', 'planetwork', 'postrank', 'proximic', 'purebot', 'pycurl', 'queryn', 'queryseeker', 'radian6', 'radiation', 'realdownload', 'remoteview', 'rogerbot', 'scooter', 'seekerspider', 'semalt', '(c99|php|web)shell', 'shellshock', 'siclab', 'sindice', 'sistrix', 'sitebot', 'site(.*)copier', 'siteexplorer', 'sitesnagger', 'skygrid', 'smartdownload', 'snoopy', 'sosospider', 'spankbot', 'spbot', 'sqlmap', 'stackrambler', 'stripper', 'sucker', 'surftbot', 'sux0r', 'suzukacz', 'suzuran', 'takeout', 'teleport', 'telesoft', 'true_robots', 'turingos', 'turnit', 'unserialize', 'vampire', 'vikspider', 'voideye', 'webleacher', 'webreaper', 'webstripper', 'webvac', 'webviewer', 'webwhacker', 'winhttp', 'wwwoffle', 'woxbot', 'x22', 'xaldon', 'xxxyy', 'yamanalab', 'yioopbot', 'youda', 'zeus', 'zmeu', 'zyborg']);

    $referrer_array = apply_filters('securelywp_referrer_items', ['@unlink', '100dollars', 'assert\(', 'best-seo', 'blue\s?pill', 'cocaine', 'ejaculat', 'erectile', 'erections', 'hoodia', 'huronriver', 'impotence', 'levitra', 'libido', 'lipitor', 'mopub\.com', 'phentermin', 'print_r\(', 'pro[sz]ac', 'sandyauer', 'semalt\.com', 'todaperfeita', 'tramadol', 'ultram', 'unicauca', 'valium', 'viagra', 'vicodin', 'x00', 'xanax', 'xbshell', 'ypxaieo']);
	
    $post_array = apply_filters('securelywp_post_items', ['<%=', '\+\/"\/\+\/', '(<|%3C|&lt;?|u003c|x3c)script', 'src=#\s', '(href|src)="javascript:', '(href|src)=javascript:', '(href|src)=`javascript:']);
    
    // Custom rules from settings
    $custom_rules = isset($options['custom_rules']) ? explode("\n", $options['custom_rules']) : [];
    $custom_rules = array_filter(array_map('trim', $custom_rules), function($rule) {
        return !empty($rule) && @preg_match("/$rule/", '') !== false;
    });

    $request_uri_string = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $query_string_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
    $user_agent_string = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $referrer_string = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    $post_string = !empty($_POST) ? wp_json_encode(wp_unslash($_POST)) : '';

    // Whitelist check
    $whitelist = isset($options['whitelist']) ? explode("\n", $options['whitelist']) : [];
    $whitelist = array_filter(array_map('trim', $whitelist));
    foreach ($whitelist as $pattern) {
        if (!empty($pattern) && (
            preg_match("/$pattern/i", $request_uri_string) ||
            preg_match("/$pattern/i", $query_string_string) ||
            preg_match("/$pattern/i", $user_agent_string)
        )) {
            return; // Skip if matches whitelist
        }
    }

    // Long request check
    $long_requests = apply_filters('securelywp_long_requests', true);
    $long_req_length = apply_filters('securelywp_long_req_length', 2000);
    if (!empty($options['check_long_requests']) && $long_requests && (strlen($request_uri_string) > $long_req_length)) {
        securelywp_firewall_block(['Long request']);
    }

    // Check request URI
    if (!empty($options['check_request_uri']) && $request_uri_string && preg_match('/' . implode('|', array_merge($request_uri_array, $custom_rules)) . '/i', $request_uri_string, $matches)) {
        securelywp_firewall_block($matches);
    }

    // Check query string
    if (!empty($options['check_query_string']) && $query_string_string && preg_match('/' . implode('|', array_merge($query_string_array, $custom_rules)) . '/i', $query_string_string, $matches)) {
        securelywp_firewall_block($matches);
    }

    // Check user agent
    if (!empty($options['check_user_agent']) && $user_agent_string && preg_match('/' . implode('|', array_merge($user_agent_array, $custom_rules)) . '/i', $user_agent_string, $matches)) {
        securelywp_firewall_block($matches);
    }

    // Check referrer
    if (!empty($options['check_referrer']) && $referrer_string && preg_match('/' . implode('|', array_merge($referrer_array, $custom_rules)) . '/i', $referrer_string, $matches)) {
        securelywp_firewall_block($matches);
    }

    // Check POST body
    if (!empty($options['check_post_body']) && $post_string && preg_match('/' . implode('|', array_merge($post_array, $custom_rules)) . '/i', $post_string, $matches)) {
        securelywp_firewall_block($matches);
    }
}
add_action('plugins_loaded', 'securelywp_firewall_core', 1);

/**
 * Handle blocked requests
 *
 * @param array $matches The matched patterns
 */
function securelywp_firewall_block($matches) {
    do_action('securelywp_firewall_block', $matches);

    $match = isset($matches[0]) ? $matches[0] : 'Unknown';
    $log_entry = [
        'time' => current_time('mysql'),
        'match' => sanitize_text_field($match),
        'uri' => isset($_SERVER['REQUEST_URI']) ? sanitize_text_field($_SERVER['REQUEST_URI']) : '',
        'ip' => sanitize_text_field(securelywp_get_client_ip()),
    ];

    // Store recent blocked requests (limited to 50)
    $blocked_requests = get_option('securelywp_blocked_requests', []);
    $blocked_requests[] = $log_entry;
    if (count($blocked_requests) > 50) {
        $blocked_requests = array_slice($blocked_requests, -50);
    }
    update_option('securelywp_blocked_requests', $blocked_requests, false);

    // Send 403 response
    header('HTTP/1.1 403 Forbidden');
    header('Status: 403 Forbidden');
    header('Connection: Close');
    exit;
}

/**
 * Validate a regex pattern
 *
 * @param string $pattern The regex pattern to validate
 * @return bool True if valid, false otherwise
 */
function securelywp_validate_regex($pattern) {
    return @preg_match("/$pattern/", '') !== false;
}