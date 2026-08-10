<?php
/**
 * SecurelyWP Disable XML-RPC
 *
 * Disables XML-RPC to reduce attack surface and improve performance.
 *
 * @package SecurelyWP
 * @since 1.2.1
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Class SecurelyWP_Disable_XMLRPC
 */
class SecurelyWP_Disable_XMLRPC {
    /**
     * Constructor.
     */
    public function __construct() {
        $options = get_option('securelywp_hardening_options', []);

        if (!empty($options['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', [$this, 'remove_xmlrpc_methods']);
        }
    }

    /**
     * Remove XML-RPC methods.
     *
     * @param array $methods Registered methods.
     * @return array
     */
    public function remove_xmlrpc_methods($methods) {
        unset(
            $methods['pingback.ping'],
            $methods['wp.getUsersBlogs'],
            $methods['wp.newPost'],
            $methods['wp.editPost'],
            $methods['wp.deletePost'],
            $methods['wp.getComments'],
            $methods['wp.newComment'],
            $methods['wp.editComment'],
            $methods['wp.deleteComment'],
            $methods['wp.getPostTypes'],
            $methods['wp.getPostStatuses'],
            $methods['wp.getTaxonomies'],
            $methods['wp.getOptions'],
            $methods['wp.setOptions'],
            $methods['wp.uploadFile'],
            $methods['wp.getMediaLibrary']
        );

        return $methods;
    }
}

new SecurelyWP_Disable_XMLRPC();