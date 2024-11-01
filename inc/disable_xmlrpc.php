<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

if (!function_exists('wp_firewall_disable_xmlrpc')) {
    function wp_firewall_disable_xmlrpc(){
        global $wp_firewall;

        if( !$wp_firewall ){
            return;
        }

        remove_action('wp_head', 'rsd_link');
        
        add_filter('xmlrpc_enabled', '__return_false');
    }
}