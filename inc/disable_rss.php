<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

if (!function_exists('wp_firewall_disable_rss')) {
    function wp_firewall_disable_rss(){
        global $wp_firewall;

        if( !$wp_firewall ){
            return;
        }

        remove_action('wp_head', 'feed_links', 2 );
        remove_action('wp_head', 'feed_links_extra', 3 );
        
        add_action('do_feed', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_rdf', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_rss', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_rss2', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_atom', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_rss2_comments', array( $wp_firewall, 'return_disabled_screen' ), -1);
        add_action('do_feed_atom_comments', array( $wp_firewall, 'return_disabled_screen' ), -1);
    }
}