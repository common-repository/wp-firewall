<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

if (!function_exists('wp_firewall_disable_wlwmanifest')) {
    function wp_firewall_disable_wlwmanifest(){
        global $wp_firewall;

        if( !$wp_firewall ){
            return;
        }

        remove_action('wp_head', 'wlwmanifest_link');
    }
}