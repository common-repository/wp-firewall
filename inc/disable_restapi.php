<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

if (!function_exists('wp_firewall_disable_restapi')) {
    function wp_firewall_disable_restapi(){
        global $wp_firewall;

        if( !$wp_firewall ){
            return;
        }

        remove_action('wp_head', 'rest_output_link_wp_head', 10);
        remove_action('wp_head', 'wp_oembed_add_discovery_links', 10);
        remove_action('template_redirect', 'rest_output_link_header', 11, 0);
    }
}