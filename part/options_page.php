<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

?>
<div class="wrap">
    <h1><?php _e('Firewall settings', 'wp-firewall');?></h1>

    <form method="post" action="options.php" id="wp-firewall-options-form">
        <?php settings_fields( 'wp-firewall-settings' ); ?>
        <?php 
        do_settings_sections( 'wp-firewall-settings' );

        $all_enabled_rules = get_option('wp_firewall_enabled_rules') ? get_option('wp_firewall_enabled_rules') : array();

        $htaccess_rules = isset( $all_enabled_rules['htaccess'] ) ? $all_enabled_rules['htaccess'] : array();

        $php_rules = isset( $all_enabled_rules['php'] ) ? $all_enabled_rules['php'] : array();

        ?>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Enable firewall', 'wp-firewall');?></th>
                <td>
                    <?php if( empty(get_option('wp_firewall_is_enabled')) || get_option('wp_firewall_is_enabled') == 0 ){ ?>
                    <button class="button button-primary" name="wp_firewall_is_enabled" value="1"><?php _e('Activate', 'wp-firewall');?></button>
                    <?php } else { ?>
                    <button class="button button-secondary" name="wp_firewall_is_enabled" value="0"><?php _e('Disable', 'wp-firewall');?></button>
                    <?php } ?>
                </td>
            </tr>
        </table>

        <?php if( empty(get_option('wp_firewall_is_enabled')) || get_option('wp_firewall_is_enabled') == 0 ){ ?>
        <hr>

        <h2><?php _e('Additional rules', 'wp-firewall');?></h2>
        <p><?php _e('Choose which additional rules to include in your .htaccess file.<br>These rules help the CMS improve its performance or extend its functionality.', 'wp-firewall');?></p>
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Header caching / expired', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_header_caching"<?php echo in_array('wp_firewall_header_caching', $htaccess_rules) ? ' checked="checked"' : '';?> />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Disable RSS feeds', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[php][]" value="wp_firewall_stop_rss"<?php echo in_array('wp_firewall_stop_rss', $php_rules) ? ' checked="checked"' : '';?> />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Disable REST API', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[php][]" value="wp_firewall_stop_restapi"<?php echo in_array('wp_firewall_stop_restapi', $php_rules) ? ' checked="checked"' : '';?> />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <!--<tr valign="top">
<th scope="row"><?php printf( __('Enable <a href="%s" target="_blank">%s</a> on forms', 'wp-firewall'), 'https://developers.google.com/recaptcha', __('reCAPTCHA v2 (invisible)', 'wp-firewall') );?></th>
<td><label><input type="checkbox" name="wp_firewall_enabled_rules[php][]" value="wp_firewall_form_recaptcha"<?php echo in_array('wp_firewall_form_recaptcha', $php_rules) ? ' checked="checked"' : '';?> /> <?php _e('Include', 'wp-firewall');?> - <strong title="<?php _e('This is a EXTRA features, for any problem try to exclude it', 'wp-firewall');?>"><?php _e('EXTRA', 'wp-firewall');?></strong></label><br><br>
<input type="text" name="wp_firewall_enabled_rules[php][g_recaptcha][website_key]" value="<?php echo ( isset($php_rules['g_recaptcha']['website_key']) ? $php_rules['g_recaptcha']['secret_key'] : '' );?>" placeholder="<?php _e('Website key', 'wp-firewall');?>"><br><br>
<input type="text" name="wp_firewall_enabled_rules[php][g_recaptcha][secret_key]" value="<?php echo ( isset($php_rules['g_recaptcha']['secret_key']) ? $php_rules['g_recaptcha']['secret_key'] : '' );?>" placeholder="<?php _e('Secret key', 'wp-firewall');?>"></td>
</tr>-->
        </table>

        <hr>

        <h2><?php _e('Protection rules', 'wp-firewall');?></h2>
        <p><?php _e('Choose which protection rules to include in your .htaccess file.<br>To make the changes effective, remember to <strong>disable and re-enable the firewall</strong> (first option).<br>The modification of these settings is recommended only for experienced developers.', 'wp-firewall');?></p>
        <input type="hidden" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_basic_rules" />
        <table class="form-table">
            <tr valign="top">
                <th scope="row"><?php _e('Basic protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" checked="checked" disabled="disabled" />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Headers protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_headers_rules"<?php echo in_array('wp_firewall_headers_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Users protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_users_rules"<?php echo in_array('wp_firewall_users_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('SPAM protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_spam_rules"<?php echo in_array('wp_firewall_spam_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Indexes protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_indexes_rules"<?php echo in_array('wp_firewall_indexes_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Files protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_files_rules"<?php echo in_array('wp_firewall_files_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Images hotlinking protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_images_rules"<?php echo in_array('wp_firewall_images_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('Iniectons and requests protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_iniectons_rules"<?php echo in_array('wp_firewall_iniectons_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('6G firewall protection rules', 'wp-firewall');?></th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_6g_rules"<?php echo in_array('wp_firewall_6g_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
            <tr valign="top">
                <th scope="row"><?php _e('7G firewall protection rules', 'wp-firewall');?> *</th>
                <td><label class="switch">
                    <input type="checkbox" name="wp_firewall_enabled_rules[htaccess][]" value="wp_firewall_7g_rules"<?php echo in_array('wp_firewall_7g_rules', $htaccess_rules) ? ' checked="checked"' : '';?>  />
                    <span class="slider"></span>
                    </label></td>
            </tr>
        </table>
        <p>* <strong><?php _e('This is a BETA features, for any problem try to exclude it.', 'wp-firewall');?></strong></p>
        <?php //submit_button(); ?>
        <hr>
        <?php } else {
    foreach($htaccess_rules as $active_rule){
        echo '<input type="hidden" value="'.$active_rule.'" name="wp_firewall_enabled_rules[htaccess][]">' . "\n";
    }
    foreach($php_rules as $active_rule){
        echo '<input type="hidden" value="'.$active_rule.'" name="wp_firewall_enabled_rules[php][]">' . "\n";
    }
    $count_total_actived_rules = count($htaccess_rules) + count($php_rules);
        ?>
        <p><?php printf( _n( '<u><strong>%s</strong></u> active protection rule', '<u><strong>%s</strong></u> active protection rules', $count_total_actived_rules, 'wp-firewall' ), number_format_i18n( $count_total_actived_rules ) );?></p>
        <div class="wp-firewall-notice">
            <div class="wp-firewall-notice-icon"><span class="dashicons dashicons-shield"></span></div>
            <div class="wp-firewall-notice-body">
                <div class="wp-firewall-notice-title"><?php _e('Congratulations!', 'wp-firewall');?></div>
                <div class="wp-firewall-notice-content"><?php _e('All the chosen rules are active.<br>To change the rules, disable the protection.', 'wp-firewall');?></div>
                <div class="wp-firewall-notice-actions"><?php printf( '<a href="%s" target="_blank" class="button button-primary"> %s </a>', 'https://wordpress.org/support/plugin/wp-firewall/reviews/?filter=5', __( 'Review plugin', 'wp-firewall' ) );?> <?php printf( '<a href="%s" target="_blank" class="button button-secondary"> %s </a>', 'https://wordpress.org/support/plugin/wp-firewall/', __( 'Plugin support', 'wp-firewall' ) );?></div>
            </div>
        </div>
        <?php } ?>
        <small class="wp-firewall-powered-by"><?php printf( 'Created by <a href="%s" target="_blank" title="Freelance web developer">Andrea De Giovine</a>. Go to <a href="%s" target="_blank">WordPress.org Plugin Page</a>.', 'https://www.andreadegiovine.it', 'https://it.wordpress.org/plugins/wp-firewall/' );?></small>
    </form>
</div>