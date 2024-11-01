<?php
/*
Plugin Name: WP Firewall
Plugin URI: https://www.andreadegiovine.it/download/wp-firewall/?utm_source=wordpress_org&utm_medium=plugin_link&utm_campaign=wp_firewall
Description: Protect WordPress from hacker attacks, spam and dangerous actions.
Author: Andrea De Giovine
Author URI: https://www.andreadegiovine.it/?utm_source=wordpress_org&utm_medium=plugin_details&utm_campaign=wp_firewall
Text Domain: wp-firewall
Domain Path: /languages/
Version: 2.1.2
*/

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

foreach ( glob( plugin_dir_path( __FILE__ ) . "inc/*.php" ) as $file ) {
    include_once $file;
}

if ( ! class_exists( 'wp_firewall' ) ) {
    class wp_firewall {

        public $protocol = '';
        public $url = '';
        public $path = '';

        public $rules = array();
        public $is_protected = false;

        public function __construct(){
            $url_blog = get_bloginfo( 'url' ); // https://www.andreadegiovine.it
            $this->protocol = explode('://', $url_blog)[0]; // https
            $this->url = explode('://', $url_blog)[1]; // www.andreadegiovine.it
            $this->path = ABSPATH; // /var/www/htdocs/
            $this->is_protected = $this->is_protected();
        }

        public function init_plugin(){
            add_action( 'plugins_loaded', array( $this, 'apply_upgrade' ) );
            add_action( 'init', array( $this, 'init_load_textdomain' ) );

            register_activation_hook( __FILE__, array( $this, 'plugin_reset' ) );
            register_deactivation_hook( __FILE__, array( $this, 'plugin_reset' ) );

            if ( !is_multisite() ) { 
                add_action( 'admin_menu', array( $this, 'init_options_menu' ));
            } else {
                add_action( 'network_admin_menu', array( $this, 'init_network_options_menu' ));
            }

            add_filter( 'plugin_action_links', array( $this, 'init_plugin_action_links' ), 10, 2 );

            add_action( 'admin_init', array( $this, 'apply_htaccess_firewall' ));
            add_action( 'admin_notices', array( $this, 'init_admin_notice') );
            add_action( 'admin_enqueue_scripts', array( $this, 'wp_admin_enqueue') );

            add_action( 'init', array( $this, 'apply_php_firewall' ));
        }

        public function apply_upgrade(){
            if (!function_exists('get_plugin_data')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $plugin_data = get_plugin_data( __FILE__ );
            $plugin_version = $plugin_data['Version'];
            $installed_plugin_version = get_option( 'wp_firewall_version', false );
            if($plugin_version !== $installed_plugin_version){ // db need upgrade
                if(!$installed_plugin_version){ // after 2.1.2
                    $this->plugin_reset();
                }
                update_option( "wp_firewall_version", $plugin_version );
            }
        }

        public function wp_admin_enqueue() {
            wp_register_style( 'wp-firewall', plugins_url( 'assets/admin-ui.css', __FILE__ ), false, '1.0.0' );
            wp_enqueue_style( 'wp-firewall' );
        }

        public function init_admin_notice(){
            $screen = get_current_screen();

            if(!$this->htaccess_exists()){
?>
<div class="notice notice-error">
    <p><?php _e('<strong>WP FIREWALL NOTICE</strong>', 'wp-firewall');?></p>
    <p><?php _e('It appears that the .htaccess file is not present in the main site folder.<br>Try changing or refreshing the permalink settings (Settings > Permalink).', 'wp-firewall');?></p>
    <p><a class="button" href="<?php echo esc_url( admin_url( 'options-permalink.php' ) );?>"><?php _e('Permalink settings', 'wp-firewall');?></a></p>
</div>
<?php
                                         }

            if(get_option('wp_firewall_is_enabled') != 1 && $screen->id !== 'settings_page_firewall'){
?>
<div class="notice notice-error">
    <p><?php _e('<strong>WP FIREWALL NOTICE</strong>', 'wp-firewall');?></p>
    <p><?php _e('The plugin is active but the <strong>protection is not enabled</strong>.<br>Enable protection from the plugin options page (Settings > Firewall).', 'wp-firewall');?></p>
    <p><a class="button" href="<?php menu_page_url( 'firewall' );?>"><?php _e('Firewall settings', 'wp-firewall');?></a></p>
</div>
<?php
                                                                                                     }

        }

        public function apply_htaccess_firewall(){
            if(get_option('wp_firewall_is_enabled') == 1 && !$this->is_protected){
                $all_enabled_rules = get_option('wp_firewall_enabled_rules') ? get_option('wp_firewall_enabled_rules') : array();
                $htaccess_rules = isset( $all_enabled_rules['htaccess'] ) ? $all_enabled_rules['htaccess'] : array();
                $this->write_rules($htaccess_rules);
            } elseif(get_option('wp_firewall_is_enabled') != 1 && $this->is_protected) {
                $this->remove_rules();
            }
        }

        public function apply_php_firewall(){
            if(get_option('wp_firewall_is_enabled') != 1) {
                return;
            }

            add_filter('the_generator', '__return_false');

            $all_enabled_rules = get_option('wp_firewall_enabled_rules') ? get_option('wp_firewall_enabled_rules') : array();
            $php_rules = isset( $all_enabled_rules['php'] ) ? $all_enabled_rules['php'] : array();
            $htaccess_rules = isset( $all_enabled_rules['htaccess'] ) ? $all_enabled_rules['htaccess'] : array();

            if( in_array('wp_firewall_stop_rss', $php_rules) ){
                wp_firewall_disable_rss();
            }

            if( in_array('wp_firewall_stop_restapi', $php_rules) ){
                wp_firewall_disable_restapi();
            }

            if( in_array('wp_firewall_files_rules', $htaccess_rules) ){
                wp_firewall_disable_xmlrpc();
                wp_firewall_disable_wlwmanifest();
            }

        }

        public function return_disabled_screen(){
            wp_die( sprintf( __( 'Content disabled by "WP Firewall" plugin, visit %s <a href="%s">homepage</a>.', 'wp-firewall' ), get_bloginfo('name'), site_url() ) );
        }

        public function init_plugin_action_links($links, $file){
            if ( $file == 'wp-firewall/wp-firewall.php' ) {
                $links[] = sprintf( '<a href="%s"> %s </a>', menu_page_url( 'firewall', false ), __( 'Settings', 'wp-firewall' ) );
                $links[] = sprintf( '<a href="%s" target="_blank"> %s </a>', 'https://wordpress.org/support/plugin/wp-firewall/reviews/?filter=5', __( 'Review plugin', 'wp-firewall' ) );
            }
            return $links;
        }

        public function plugin_reset(){
            delete_option( 'wp_firewall_is_enabled' );
            delete_option( 'wp_firewall_enabled_rules' );
            $this->remove_rules();
        }

        public function htaccess_exists(){
            $exists = false;
            $htaccess = ABSPATH.".htaccess";
            if(file_exists($htaccess)){
                $exists = true;
            }
            return $exists;
        }

        public function init_options_menu(){
            add_submenu_page( 'options-general.php', __('WP Firewall settings', 'wp-firewall'), __('Firewall', 'wp-firewall'), 'administrator', 'firewall', array( $this, 'init_options_page' ) );
            add_action( 'admin_init', array( $this, 'settings_options_page' ) );
        }

        public function init_network_options_menu(){            
            add_menu_page( __('WP Firewall settings', 'wp-firewall'), __('Firewall', 'wp-firewall'), 'administrator', 'firewall', array( $this, 'init_options_page' ), 'dashicons-shield' );
            add_action( 'admin_init', array( $this, 'settings_options_page' ) );
        }

        public function init_options_page(){
            require_once( plugin_dir_path( __FILE__ ) . 'part/options_page.php');
        }

        public function settings_options_page(){
            register_setting( 'wp-firewall-settings', 'wp_firewall_is_enabled' );
            register_setting( 'wp-firewall-settings', 'wp_firewall_enabled_rules' );
        }

        public function init_load_textdomain() {
            load_plugin_textdomain( 'custom-post-types', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' ); 
        }

        public function is_protected(){
            $is_protected = false;
            $htaccess = ABSPATH.".htaccess";
            if($this->htaccess_exists()){
                $is_protected = strpos(file_get_contents($htaccess),'# BEGIN WP Firewall');
            }

            return $is_protected;
        }

        public function write_rules($rules){
            if (!function_exists('get_home_path')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }
            if (!function_exists('insert_with_markers')) {
                require_once ABSPATH . 'wp-admin/includes/misc.php';
            }

            $htaccess = get_home_path().".htaccess";


            if (file_exists($htaccess) && !is_writable($htaccess)) { // Change .htaccess file permissions
                $file_existing_permission = substr(decoct(fileperms($htaccess)), -4);
                chmod($htaccess, 0777);
            }


            $all_rules = $this->rules;
            $write_rules = array();
            $write_rules[] = "# Rules added by WP Firewall plugin, for any problem remove it.";
            $write_rules[] = "";
            foreach($rules as $rule){
                if(isset($all_rules[$rule]) && !empty($all_rules[$rule])){
                    $write_rules[] = $all_rules[$rule];
                }
            }
            $write_rules[] = "";
            if(insert_with_markers($htaccess, "WP Firewall", $write_rules)){
                return true;
            } else {
                return false;
            }

            if (!empty($file_existing_permission)) { // Restore .htaccess file permissions
                chmod($htaccess, $file_existing_permission);
            }
        }

        public function remove_rules(){
            if (!function_exists('get_home_path')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }
            $htaccess = get_home_path().".htaccess";
            $markerdata = explode("\n", implode('', file($htaccess)));
            $found = false;
            $newdata = '';
            foreach ($markerdata as $line) {
                if ($line == '# BEGIN WP Firewall') {
                    $found = true;
                }
                if (!$found) {
                    $newdata .= "{$line}\n";
                }
                if ($line == '# END WP Firewall') {
                    $found = false;
                }
            }
            // write back
            $f = @fopen($htaccess, 'w');
            if(fwrite($f, $newdata)){
                return true;
            } else {
                return false;
            }
        }       

    }
    $wp_firewall = new wp_firewall();
    $wp_firewall->rules = wp_firewall_htaccess_rules();
    $wp_firewall->init_plugin();
}