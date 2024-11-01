<?php

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Invalid request.' );
}

if (!function_exists('wp_firewall_htaccess_rules')) {
    function wp_firewall_htaccess_rules(){
        global $wp_firewall;
        
        if( !$wp_firewall ){
            return;
        }
        
        $rules = array();

        $rules['wp_firewall_basic_rules'] = '# Basic rules

# Security Admin for Multisite or dinamic IP Adress
ErrorDocument 401 '.$wp_firewall->path.'index.php?error=404
ErrorDocument 403 '.$wp_firewall->path.'index.php?error=404

<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_METHOD} POST
RewriteCond !^'.$wp_firewall->protocol.'://(.*)?'.(explode('.',$wp_firewall->url)[0] === 'www' ? str_replace("www.", "", $wp_firewall->url) : $wp_firewall->url ).' [NC]
RewriteCond %{REQUEST_URI} ^(.*)?wp-login\.php(.*)$ [OR]
RewriteCond %{REQUEST_URI} ^(.*)?wp-admin$
RewriteRule ^(.*)$ - [F]
</IfModule>

# Protect wp-content
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /wp-content/.*$ [NC]
RewriteCond %{REQUEST_FILENAME} !^.+flexible-upload-wp25js.php$
RewriteCond %{REQUEST_FILENAME} ^.+\.(php|html|htm|txt)$
RewriteRule .? - [F,NS,L]
</IfModule>

# Block direct access to your plugin and theme
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_URI} !^/wp-content/plugins/file/to/exclude\.php
RewriteCond %{REQUEST_URI} !^/wp-content/plugins/directory/to/exclude/
RewriteRule wp-content/plugins/(.*\.php)$ - [R=404,L]
RewriteCond %{REQUEST_URI} !^/wp-content/themes/file/to/exclude\.php
RewriteCond %{REQUEST_URI} !^/wp-content/themes/directory/to/exclude/
RewriteRule wp-content/themes/(.*\.php)$ - [R=404,L]
</IfModule>

# Protect wp-includes
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /wp-includes/.*$ [NC]
RewriteCond %{THE_REQUEST} !^[A-Z]{3,9}\ /wp-includes/js/.+/.+\ HTTP/ [NC]
RewriteCond %{REQUEST_FILENAME} ^.+\.php$
RewriteRule .? - [F,NS,L]
</IfModule>

# Block Include-Only Files
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

# Block direct access to your wp-include
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_URI} !^/wp-includes/file/to/exclude\.php
RewriteCond %{REQUEST_URI} !^/wp-includes/directory/to/exclude/
RewriteRule wp-includes/(.*\.php)$ - [R=404,L]
</IfModule>

# Block direct access to your uploads
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{REQUEST_URI} !^/wp-content/uploads/file/to/exclude\.php
RewriteCond %{REQUEST_URI} !^/wp-content/uploads/directory/to/exclude/
RewriteRule wp-content/uploads/(.*\.php)$ - [R=404,L]
</IfModule>

# Prevent subfolder loading. This goes
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{HTTP_HOST} ^primary\.com$ [OR]
RewriteCond %{HTTP_HOST} ^www\.primary\.com$
RewriteRule ^addon\.com\/?(.*)$ "http\:\/\/www\.addon\.com\/$1" [R=301,L]
</IfModule>

# Always use https for secure connections
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{SERVER_PORT} 80
RewriteRule ^(.*)$ '.$wp_firewall->protocol.'://'.$wp_firewall->url.'/$1 [R=301,L]
</IfModule>

# Correct URL Typo Automatically
<ifmodule mod_speling.c>
CheckSpelling On
</ifmodule>

# Add .php to access file, but dont redirect
<IfModule mod_rewrite.c>
Options +FollowSymLinks -MultiViews -indexes
RewriteEngine On
RewriteBase /
RewriteCond %{REQUEST_FILENAME}.php -f
RewriteCond %{REQUEST_URI} !/$
RewriteRule (.*) $1.php [L]
</IfModule>';

        $rules['wp_firewall_headers_rules'] = '# Headers rules

# No-Referrer-Header
<IfModule mod_headers.c>
    Header set Referrer-Policy "no-referrer"
</IfModule>

# X-FRAME-OPTIONS-Header
<IfModule mod_headers.c>
    Header set X-Frame-Options "sameorigin"
</IfModule>

# X-XSS-PROTECTION-Header
<IfModule mod_headers.c>
    Header set X-XSS-Protection "1; mode=block"
</IfModule>

# X-Content-Type-Options-Header
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
</IfModule>

# Prevent false certificate (experimental)
<IfModule mod_headers.c>
   Header set Expect-CT "enforce, max-age=21600"	
</IfModule>

# Unset headers revealing versions strings
<IfModule mod_headers.c>
  Header unset X-Powered-By
  Header unset X-Pingback
  Header unset SERVER
</IfModule>

# Force secure cookies (uncomment for HTTPS)
<IfModule mod_headers.c>
  #Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
</IfModule>

# Blocking based on User-Agent Header
<IfModule mod_headers.c>
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} ^.*(craftbot|download|extract|stripper|sucker|ninja|clshttp|webspider|leacher|collector|grabber|webpictures).*$ [NC]
RewriteRule . - [F,L]
</IfModule>';

        $rules['wp_firewall_users_rules'] = '# Users rules

# Block author scans
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteCond %{QUERY_STRING} (author=\d+) [NC]
RewriteRule .* - [F]
</IfModule>

# Stop Username Enumeration Attacks
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/wp-admin [NC]
RewriteCond %{QUERY_STRING} author=\d
RewriteRule .* - [R=403,L]
</IfModule>

# Block User list Phishing Requests
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} ^author=([0-9]*)
RewriteRule .* '.$wp_firewall->protocol.'://'.$wp_firewall->url.'/? [L,R=302]
</IfModule>';

        $rules['wp_firewall_spam_rules'] = '# SPAM rules

# Denies any POST Request using a Proxy Server. Can still access site, but not comment.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} =POST
RewriteCond %{HTTP:VIA}%{HTTP:FORWARDED}%{HTTP:USERAGENT_VIA}%{HTTP:X_FORWARDED_FOR}%{HTTP:PROXY_CONNECTION} !^$ [OR]
RewriteCond %{HTTP:XPROXY_CONNECTION}%{HTTP:HTTP_PC_REMOTE_ADDR}%{HTTP:HTTP_CLIENT_IP} !^$
RewriteCond %{REQUEST_URI} !^/(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Block any POST attempt made to a non-existing wp-comments-post.php
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*/wp-comments-post\.php.*\ HTTP/ [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Block any POST request that doesnt have a Content-Length Header
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} =POST
RewriteCond %{HTTP:Content-Length} ^$
RewriteCond %{REQUEST_URI} !^/(wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Block any POST request with a content type other than application/x-www-form-urlencoded|multipart/form-data
#<IfModule mod_rewrite.c>
#RewriteEngine On
#RewriteCond %{REQUEST_METHOD} =POST
#RewriteCond %{HTTP:Content-Type} !^(application/x-www-form-urlencoded|multipart/form-data.*(boundary.*)?)$ [NC]
#RewriteCond %{REQUEST_URI} !^/(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
#RewriteRule .? - [F,NS,L]
#</IfModule>

# Block POST requests by blank user-agents. May prevent a small number of visitors from POSTING
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} =POST
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Denies any comment attempt with a blank HTTP_REFERER field, highly indicative of spam. May prevent some visitors from POSTING
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.*/wp-comments-post\.php.*\ HTTP/ [NC]
RewriteCond %{HTTP_REFERER} ^-?$
RewriteRule .? - [F,NS,L]
</IfModule>

# Trackback Spam
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} =POST
RewriteCond %{HTTP_USER_AGENT} ^.*(opera|mozilla|firefox|msie|safari).*$ [NC]
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /.+/trackback/?\ HTTP/ [NC]
RewriteRule .? - [F,NS,L]
</IfModule>';

        $rules['wp_firewall_indexes_rules'] = '# Indexes rules

# Dont list directories
<IfModule mod_autoindex.c>
  Options -Indexes
</IfModule>

# Remove index
<IfModule mod_rewrite.c>
Options +FollowSymLinks -MultiViews -indexes
RewriteEngine On
RewriteBase /
RewriteCond %{THE_REQUEST} /index(\.php)?[\s?/] [NC]
RewriteRule ^(.*?)index(/|$) /$1 [L,R=301,NC,NE]
</IfModule>

# Remove index and slash if not directory
<IfModule mod_rewrite.c>
Options +FollowSymLinks -MultiViews -indexes
RewriteEngine On
RewriteBase /
RewriteRule (.*)/index$ $1/ [R=302]
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} /$
RewriteRule (.*)/ $1 [R=301,L]
</IfModule>';

        $rules['wp_firewall_files_rules'] = '# Files rules

# Block access to the install.php
<files install.php>
Order allow,deny
Deny from all
</files>

# Block access to file
<FilesMatch "\.(.php|php.ini|/.[hH][tT][aApP]txt|md|exe|sh|bak|inc|pot|po|mo|log|sql|(.*)\.ttf|(.*)\.bak|xml)$">
Order allow,deny
Deny from all
</FilesMatch>

# Block access to .htaccess
<files ~ "^.*\.([Hh][Tt][Aa])">
order allow,deny
deny from all
satisfy all
</files>

# Block access to wp-config
<files wp-config.php>
order allow,deny
deny from all
</files>

# Block access to xmlrpc
<Files xmlrpc.php>
order deny,allow
deny from all
allow from 123.123.123.123
</Files>

# Block access to xmlrpc mobile
<IfModule mod_setenvif.c>
 <Files xmlrpc.php>
 BrowserMatch "Poster" allowed
 BrowserMatch "WordPress" allowed
 BrowserMatch "Windows Live Writer" allowed
 BrowserMatch "wp-iphone" allowed
 BrowserMatch "wp-android" allowed
 Order Deny,Allow
 Deny from All
 Allow from env=allowed
 </Files>
</IfModule>

# Block access to *.txt
<Files *.txt> 
	Deny from all
</Files>

# Block access to robot.txt
<Files robots.txt>
Allow from all
</Files>

# Block access to ads.txt
<Files ads.txt>
Allow from all
</Files>

# Block access to error_log
<files error_log>
order allow,deny
deny from all
</files>

# Block access to the readme.html
<files readme.html>
 Order Allow,Deny
 Deny from all
 Satisfy all
</Files>

# Block access to cofiguration file
<Files php.ini> 
	Order Allow,Deny
	Deny from all
</Files>

# Block access to php5 configuration file
<Files php5.ini> 
	Order Allow,Deny
	Deny from all
</Files>

# Block access to php7 configuration file
<Files php7.ini> 
	Order Allow,Deny
	Deny from all
</Files>

# Block Access to .htpasswd
<FilesMatch "(\.htpasswd)">
  Order deny,allow
  Deny from all
</FilesMatch>';

        $rules['wp_firewall_images_rules'] = '# Images hotlinking rules

# Disable Image Hotlinking
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_REFERER} !^$
RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?'.$wp_firewall->url.' [NC]
RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?'.$wp_firewall->url.' [NC]
RewriteRule \.(jpg|jpeg|png|gif)$ http://i.imgur.com/g7ptdBB.png [NC,R,L]
</ifmodule>';

        $rules['wp_firewall_iniectons_rules'] = '# Iniectons rules

# Denies requests that dont contain a HTTP HOST Header
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
RewriteCond %{HTTP_HOST} ^$
RewriteRule .? - [F,NS,L]
</IfModule>

# Block any request not using GET,PROPFIND,POST,OPTIONS,PUT,HEAD[403]
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} !^(GET|HEAD|POST|PROPFIND|OPTIONS|PUT)$ [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Block Nuisance Requests for Non-Existent Files
<IfModule mod_alias.c>
RewriteEngine On
	RedirectMatch 403 (?i)\.php\.suspected
	RedirectMatch 403 (?i)apple-app-site-association
	RedirectMatch 403 (?i)/autodiscover/autodiscover.xml
</IfModule>

# Denies obvious exploit using bogus graphics
<IfModule mod_alias.c>
RewriteEngine On
RewriteCond %{HTTP:Content-Disposition} \.php [NC]
RewriteCond %{HTTP:Content-Type} image/.+ [NC]
RewriteRule .? - [F,NS,L]
</IfModule>

# Remove slash if not directory
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} /$
RewriteRule (.*)/ $1 [R=301,L]
</IfModule>

# Deny access to l_backuptoster.php / l_backuptoster_backup.php
#  (PHP backdoor)
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} (^/l_backuptoster.php) [NC]
RewriteRule .? - [F,L]
</ifmodule>

# Block really Long Request
<IfModule mod_rewrite.c>
RewriteEngine On
    RewriteCond %{REQUEST_METHOD} .* [NC]
    RewriteCond %{THE_REQUEST}  (YesThisIsAReallyLongRequest|ScanningForResearchPurpose) [NC,OR]
    RewriteCond %{QUERY_STRING} (YesThisIsAReallyLongRequest|ScanningForResearchPurpose) [NC]
    RewriteRule .* - [F,L]
</IfModule>

# Deny access to evil robots site rippers offline browsers and other nasty scum
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteCond %{HTTP_USER_AGENT} ^Anarchie [OR]
RewriteCond %{HTTP_USER_AGENT} ^ASPSeek [OR]
RewriteCond %{HTTP_USER_AGENT} ^attach [OR]
RewriteCond %{HTTP_USER_AGENT} ^autoemailspider [OR]
RewriteCond %{HTTP_USER_AGENT} ^Xaldon\ WebSpider [OR]
RewriteCond %{HTTP_USER_AGENT} ^Xenu [OR]
RewriteCond %{HTTP_USER_AGENT} ^Zeus.*Webster [OR]
RewriteCond %{HTTP_USER_AGENT} ^Zeus
RewriteRule ^.* - [F,L]
</IfModule>

# Protect Your Site Against Script Injections
<IfModule mod_rewrite.c>
Options +FollowSymLinks
RewriteEngine On
RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|[|%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|[|%[0-9A-Z]{0,2})
RewriteRule ^(.*)$ index.php [F,L]
</IfModule>

# File injection protection
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} GET
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http:// [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=(\.\.//?)+ [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http%3A%2F%2F [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=/([a-z0-9_.]//?)+ [NC]
RewriteRule .* - [F]
</IfModule>

# Block suspicious request methods
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(HEAD|TRACE|DELETE|TRACK|DEBUG) [NC]
RewriteRule ^(.*)$ - [F,L]
</IfModule>

# Block WP timthumb hack
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} (timthumb\.php|phpthumb\.php|thumb\.php|thumbs\.php) [NC]
RewriteRule . - [S=1]
</IfModule>

# Block suspicious user agents and requests
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|python|nikto|curl|scan|java|winhttp|clshttp|loader) [NC,OR]
RewriteCond %{HTTP_USER_AGENT} (<|>|&#8217;|%0A|%0D|%27|%3C|%3E|%00) [NC,OR]
RewriteCond %{HTTP_USER_AGENT} (;|<|>|&#8217;|"|\)|\(|%0A|%0D|%22|%27|%28|%3C|%3E|%00).*(libwww-perl|wget|python|nikto|curl|scan|java|winhttp|HTTrack|clshttp|archiver|loader|email|harvest|extract|grab|miner) [NC,OR]
RewriteCond %{THE_REQUEST} \?\ HTTP/ [NC,OR]
RewriteCond %{THE_REQUEST} \/\*\ HTTP/ [NC,OR]
RewriteCond %{THE_REQUEST} etc/passwd [NC,OR]
RewriteCond %{THE_REQUEST} cgi-bin [NC,OR]
RewriteCond %{THE_REQUEST} (%0A|%0D) [NC,OR]
</IfModule>

# Protect against SQL Injection
<IfModule mod_rewrite.c>
RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} mosConfig_[a-zA-Z_]{1,22}(=|%3D) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|exec|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>

# Block MySQL injections, RFI, base64, etc.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http:// [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http%3A%2F%2F [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=(\.\.//?)+ [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=/([a-z0-9_.]//?)+ [NC,OR]
RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC,OR]
RewriteCond %{QUERY_STRING} (\.\./|\.\.) [OR]
RewriteCond %{QUERY_STRING} ftp\: [NC,OR]
RewriteCond %{QUERY_STRING} http\: [NC,OR]
RewriteCond %{QUERY_STRING} https\: [NC,OR]
RewriteCond %{QUERY_STRING} \=\|w\| [NC,OR]
RewriteCond %{QUERY_STRING} ^(.*)/self/(.*)$ [NC,OR]
RewriteCond %{QUERY_STRING} ^(.*)cPath=http://(.*)$ [NC,OR]
RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (\<|%3C).*iframe.*(\>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^i]*i)+frame.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} base64_encode.*\(.*\) [NC,OR]
RewriteCond %{QUERY_STRING} base64_(en|de)code[^(]*\([^)]*\) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} ^.*(\[|\]|\(|\)|<|>).* [NC,OR]
RewriteCond %{QUERY_STRING} (NULL|OUTFILE|LOAD_FILE) [OR]
RewriteCond %{QUERY_STRING} (\./|\../|\.../)+(motd|etc|bin) [NC,OR]
RewriteCond %{QUERY_STRING} (localhost|loopback|127\.0\.0\.1) [NC,OR]
RewriteCond %{QUERY_STRING} (<|>|&#8217;|%0A|%0D|%27|%3C|%3E|%00) [NC,OR]
RewriteCond %{QUERY_STRING} concat[^\(]*\( [NC,OR]
RewriteCond %{QUERY_STRING} union([^s]*s)+elect [NC,OR]
RewriteCond %{QUERY_STRING} union([^a]*a)+ll([^s]*s)+elect [NC,OR]
RewriteCond %{QUERY_STRING} (;|<|>|&#8217;|"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(/\*|union|select|insert|drop|delete|update|cast|create|char|convert|alter|declare|order|script|set|md5|benchmark|encode) [NC,OR]
</IfModule>

# PHP-CGI Vulnerability
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} ^(%2d|\-)[^=]+$ [NC,OR]
</IfModule>

# Proc/self/environ? no way!
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} proc\/self\/environ [NC,OR]
RewriteCond %{QUERY_STRING} (sp_executesql) [NC]
RewriteRule ^(.*)$ - [F,L]
</IfModule>';

        $rules['wp_firewall_6g_rules'] = '# 6G firewall rules

# 6G:[QUERY STRINGS]
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST METHOD]
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|move|put|trace|track) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REFERRERS]
<IfModule mod_rewrite.c>
	RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST STRINGS]
<IfModule mod_alias.c>
	RedirectMatch 403 (?i)([a-z0-9]{2000,})
	RedirectMatch 403 (?i)(https?|ftp|php):/
	RedirectMatch 403 (?i)(base64_encode)(.*)(\()
	RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
	RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&amp;?)/?$
	RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
	RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\s|\{|\}|\[|\]|\|)
	RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|etc/passwd|muieblack)
	RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
	RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
	RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
</IfModule>

# 6G:[USER AGENTS]
<IfModule mod_setenvif.c>
	SetEnvIfNoCase User-Agent ([a-z0-9]{2000,}) bad_bot
	SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot

	# Apache < 2.3
	<IfModule !mod_authz_core.c>
		Order Allow,Deny
		Allow from all
		Deny from env=bad_bot
	</IfModule>

	# Apache >= 2.3
	<IfModule mod_authz_core.c>
		<RequireAll>
			Require all Granted
			Require not env bad_bot
		</RequireAll>
	</IfModule>
</IfModule>

# 6G:[BAD IPS]
<Limit GET HEAD OPTIONS POST PUT>
	Order Allow,Deny
	Allow from All
	# uncomment/edit/repeat next line to block IPs
	# Deny from 123.456.789
</Limit>

# Blacklist
 RewriteEngine on

 RewriteCond %{HTTP_USER_AGENT} "^Mozilla.*Indy" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Mozilla.*NEWT" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^$" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Maxthon$" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^SeaMonkey$" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Acunetix" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^binlar" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^BlackWidow" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Bolt 0" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^BOT for JCE" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Bot mailto\:craftbot@yahoo\.com" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^casper" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^checkprivacy" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^ChinaClaw" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^clshttp" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^cmsworldmap" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Custo" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Default Browser 0" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^diavol" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^DIIbot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^DISCo" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^dotbot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Download Demon" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^eCatch" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^EirGrabber" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^EmailCollector" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^EmailSiphon" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^EmailWolf" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Express WebPictures" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^extract" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^ExtractorPro" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^EyeNetIE" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^feedfinder" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^FHscan" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^FlashGet" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^flicky" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^g00g1e" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^GetRight" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^GetWeb\!" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Go\!Zilla" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Go\-Ahead\-Got\-It" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^grab" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^GrabNet" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Grafula" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^harvest" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^HMView" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Image Stripper" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Image Sucker" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^InterGET" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Internet Ninja" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^InternetSeer\.com" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^jakarta" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Java" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^JetCar" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^JOC Web Spider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^kanagawa" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^kmccrew" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^larbin" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^LeechFTP" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^libwww" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Mass Downloader" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^microsoft\.url" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^MIDown tool" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^miner" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Mister PiX" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^MSFrontPage" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Navroad" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^NearSite" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Net Vampire" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^NetAnts" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^NetSpider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^NetZIP" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^nutch" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Octopus" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Offline Explorer" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Offline Navigator" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^PageGrabber" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Papa Foto" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^pavuk" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^pcBrowser" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^PeoplePal" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^planetwork" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^psbot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^purebot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^pycurl" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^RealDownload" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^ReGet" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Rippers 0" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^sitecheck\.internetseer\.com" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^SiteSnagger" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^skygrid" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^SmartDownload" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^sucker" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^SuperBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^SuperHTTP" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Surfbot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^tAkeOut" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Teleport Pro" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Toata dragostea mea pentru diavola" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^turnit" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^vikspider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^VoidEYE" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Web Image Collector" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebAuto" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebBandit" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebCopier" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebFetch" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebGo IS" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebLeacher" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebReaper" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebSauger" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Website eXtractor" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Website Quester" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebStripper" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebWhacker" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WebZIP" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Widow" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WPScan" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WWW\-Mechanize" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^WWWOFFLE" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Xaldon WebSpider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^Zeus" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "^zmeu" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "360Spider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "CazoodleBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "discobot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "EasouSpider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "ecxi" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "GT\:\:WWW" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "heritrix" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "HTTP\:\:Lite" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "HTTrack" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "ia_archiver" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "id\-search" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "IDBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Indy Library" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "IRLbot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "ISC Systems iRc Search 2\.1" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "LinksCrawler" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "LinksManager\.com_bot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "linkwalker" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "lwp\-trivial" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "MFC_Tear_Sample" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Microsoft URL Control" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Missigua Locator" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "MJ12bot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "panscient\.com" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "PECL\:\:HTTP" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "PHPCrawl" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "PleaseCrawl" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "SBIder" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "SearchmetricsBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "SeznamBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Snoopy" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Steeler" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "URI\:\:Fetch" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "urllib" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Web Sucker" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "webalta" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "WebCollage" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "Wells Search II" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "WEP Search" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "XoviBot" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "YisouSpider" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "zermelo" [NC,OR]
 RewriteCond %{HTTP_USER_AGENT} "ZyBorg" [NC,OR]

 RewriteCond %{HTTP_REFERER} "^https?://(?:[^/]+\.)?semalt\.com" [NC,OR]
 RewriteCond %{HTTP_REFERER} "^https?://(?:[^/]+\.)?kambasoft\.com" [NC,OR]
 RewriteCond %{HTTP_REFERER} "^https?://(?:[^/]+\.)?savetubevideo\.com" [NC]

 RewriteRule ^.* - [F,L]';

        $rules['wp_firewall_7g_rules'] = '# 7G firewall rules

# 7G:[CORE]
ServerSignature Off
Options -Indexes
RewriteEngine On
RewriteBase /

# 7G:[QUERY STRING]
<IfModule mod_rewrite.c>	
	RewriteCond %{REQUEST_URI} !(7g_log.php) [NC]	
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{QUERY_STRING} (/|%2f)(:|%3a)(/|%2f) [NC,OR]
	RewriteCond %{QUERY_STRING} (/|%2f)(\*|%2a)(\*|%2a)(/|%2f) [NC,OR]
	RewriteCond %{QUERY_STRING} (~|`|<|>|\^|\|\\|0x00|%00|%0d%0a) [NC,OR]
	RewriteCond %{QUERY_STRING} (cmd|command)(=|%3d)(chdir|mkdir)(.*)(x20) [NC,OR]
	RewriteCond %{QUERY_STRING} (fck|ckfinder|fullclick|ckfinder|fckeditor) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumbs?)?)((\.|%2e)php) [NC,OR]
	RewriteCond %{QUERY_STRING} (absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?) [NC,OR]
	RewriteCond %{QUERY_STRING} (localhost|loopback|127(\.|%2e)0(\.|%2e)0(\.|%2e)1) [NC,OR]
	RewriteCond %{QUERY_STRING} (\.|20)(get|the)(_|%5f)(permalink|posts_page_url)(\(|%28) [NC,OR]
	RewriteCond %{QUERY_STRING} (s)?(ftp|http|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215)) [NC,OR]
	RewriteCond %{QUERY_STRING} (/|%2f)((wp-)?(config)(uration)?)((\.|%2e)inc)?((\.|%2e)php) [NC,OR]
	RewriteCond %{QUERY_STRING} (globals|mosconfig([a-z_]{1,22})|request)(=|[|%[a-z0-9]{0,2}) [NC,OR]
	RewriteCond %{QUERY_STRING} ((boot|win)((\.|%2e)ini)|etc(/|%2f)passwd|self(/|%2f)environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (((/|%2f){3,3})|((\.|%2e){3,3})|((\.|%2e){2,2})(/|%2f|%u2215)) [NC,OR]
	RewriteCond %{QUERY_STRING} (benchmark|char|exec|fopen|function|html)(.*)(\(|%28)(.*)(\)|%29) [NC,OR]
	RewriteCond %{QUERY_STRING} (php)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) [NC,OR]
	RewriteCond %{QUERY_STRING} (e|%65|%45)(v|%76|%56)(a|%61|%31)(l|%6c|%4c)(.*)(\(|%28)(.*)(\)|%29) [NC,OR]
	RewriteCond %{QUERY_STRING} (/|%2f)(=|%3d|$&|_mm|cgi(\.|-)|inurl(:|%3a)(/|%2f)|(mod|path)(=|%3d)(\.|%2e)) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3c)(.*)(e|%65|%45)(m|%6d|%4d)(b|%62|%42)(e|%65|%45)(d|%64|%44)(.*)(>|%3e) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3c)(.*)(i|%69|%49)(f|%66|%46)(r|%72|%52)(a|%61|%41)(m|%6d|%4d)(e|%65|%45)(.*)(>|%3e) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3c)(.*)(o|%4f|%6f)(b|%62|%42)(j|%4a|%6a)(e|%65|%45)(c|%63|%43)(t|%74|%54)(.*)(>|%3e) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3c)(.*)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(.*)(>|%3e) [NC,OR]
	RewriteCond %{QUERY_STRING} (\+|%2b|%20)(d|%64|%44)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(t|%74|%54)(e|%65|%45)(\+|%2b|%20) [NC,OR]
	RewriteCond %{QUERY_STRING} (\+|%2b|%20)(i|%69|%49)(n|%6e|%4e)(s|%73|%53)(e|%65|%45)(r|%72|%52)(t|%74|%54)(\+|%2b|%20) [NC,OR]
	RewriteCond %{QUERY_STRING} (\+|%2b|%20)(s|%73|%53)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(c|%63|%43)(t|%74|%54)(\+|%2b|%20) [NC,OR]
	RewriteCond %{QUERY_STRING} (\+|%2b|%20)(u|%75|%55)(p|%70|%50)(d|%64|%44)(a|%61|%41)(t|%74|%54)(e|%65|%45)(\+|%2b|%20) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\x00|(\"|%22|\'|%27)?0(\"|%22|\'|%27)?(=|%3d)(\"|%22|\'|%27)?0|cast(\(|%28)0x|or%201(=|%3d)1) [NC,OR]
	RewriteCond %{QUERY_STRING} (g|%67|%47)(l|%6c|%4c)(o|%6f|%4f)(b|%62|%42)(a|%61|%41)(l|%6c|%4c)(s|%73|%53)(=|[|%[0-9A-Z]{0,2}) [NC,OR]
	RewriteCond %{QUERY_STRING} (_|%5f)(r|%72|%52)(e|%65|%45)(q|%71|%51)(u|%75|%55)(e|%65|%45)(s|%73|%53)(t|%74|%54)(=|[|%[0-9A-Z]{0,2}) [NC,OR]
	RewriteCond %{QUERY_STRING} (j|%6a|%4a)(a|%61|%41)(v|%76|%56)(a|%61|%31)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(:|%3a)(.*)(;|%3b) [NC,OR]
	RewriteCond %{QUERY_STRING} (b|%62|%42)(a|%61|%41)(s|%73|%53)(e|%65|%45)(6|%36)(4|%34)(_|%5f)(e|%65|%45|d|%64|%44)(e|%65|%45|n|%6e|%4e)(c|%63|%43)(o|%6f|%4f)(d|%64|%44)(e|%65|%45)(.*)(\()(.*)(\)) [NC,OR]
	RewriteCond %{QUERY_STRING} (allow_url_(fopen|include)|auto_prepend_file|blexbot|browsersploit|(c99|php)shell|curltest|disable_functions?|document_root|elastix|encodeuricom|exec|exploit|fclose|fgets|fputs|fread|fsbuff|fsockopen|gethostbyname|grablogin|hmei7|input_file|load_file|null|open_basedir|outfile|passthru|popen|proc_open|quickbrute|remoteview|revslider|root_path|safe_mode|shell_exec|site((.){0,2})copier|sux0r|system|trojan|wget|xertive) [NC,OR]
	RewriteCond %{QUERY_STRING} (;|<|>|\'|\"|\)|%0a|%0d|%22|%27|%3c|%3e|%00)(.*)(/\*|alter|base64|benchmark|cast|char|concat|convert|create|encode|declare|delete|drop|insert|md5|order|request|script|select|set|union|update) [NC,OR]
	RewriteCond %{QUERY_STRING} ((\+|%2b)(concat|delete|get|select|union)(\+|%2b)) [NC,OR]
	RewriteCond %{QUERY_STRING} (union)(.*)(select)(.*)(\(|%28) [NC,OR]
	RewriteCond %{QUERY_STRING} (concat)(.*)(\(|%28) [NC]	
	RewriteRule . - [F,L]	
	# RewriteRule . /7g_log.php?log [L,NE,E=7G_QUERY_STRING:%1___%2___%3]	
</IfModule>

# 7G:[USER AGENT]
<IfModule mod_rewrite.c>	
	RewriteCond %{REQUEST_URI} !(7g_log.php) [NC]	
	RewriteCond %{HTTP_USER_AGENT} ([a-z0-9]{2000,}) [NC,OR]
	RewriteCond %{HTTP_USER_AGENT} (&lt;|%0a|%0d|%27|%3c|%3e|%00|0x00) [NC,OR]
	RewriteCond %{HTTP_USER_AGENT} ((c99|php|web)shell|remoteview|site((.){0,2})copier) [NC,OR]
	RewriteCond %{HTTP_USER_AGENT} (base64_decode|bin/bash|disconnect|eval|lwp-download|unserialize|\\\x22) [NC,OR]
	RewriteCond %{HTTP_USER_AGENT} (360Spider|acapbot|acoonbot|ahrefs|alexibot|archive.org|asterias|attackbot|backdorbot|becomebot|binlar|blackwidow|blekkobot|blexbot|blowfish|bullseye|bunnys|butterfly|careerbot|casper|checkpriv|cheesebot|cherrypick|chinaclaw|choppy|clshttp|cmsworld|copernic|copyrightcheck|cosmos|crescent|cy_cho|datacha|demon|diavol|discobot|dittospyder|dotbot|dotnetdotcom|dumbot|emailcollector|emailsiphon|emailwolf|exabot|extract|eyenetie|feedfinder|flaming|flashget|flicky|foobot|g00g1e|getright|gigabot|go-ahead-got|gozilla|grabnet|grafula|harvest|heritrix|httrack|icarus6j|jetbot|jetcar|jikespider|kmccrew|leechftp|libweb|linkextractor|linkscan|linkwalker|loader|miner|mj12bot|majestic|mechanize|morfeus|moveoverbot|netmechanic|netspider|nicerspro|nikto|ninja|nutch|octopus|pagegrabber|planetwork|postrank|proximic|purebot|pycurl|python|queryn|queryseeker|radian6|radiation|realdownload|rogerbot|scooter|seekerspider|semalt|seznambot|siclab|sindice|sistrix|sitebot|siteexplorer|sitesnagger|skygrid|smartdownload|snoopy|sosospider|spankbot|spbot|sqlmap|stackrambler|stripper|sucker|surftbot|sux0r|suzukacz|suzuran|takeout|teleport|telesoft|true_robots|turingos|turnit|vampire|vikspider|voideye|webleacher|webreaper|webstripper|webvac|webviewer|webwhacker|winhttp|wwwoffle|woxbot|xaldon|xxxyy|yamanalab|yioopbot|youda|zeus|zmeu|zune|zyborg) [NC]	
	RewriteRule . - [F,L]	
	# RewriteRule . /7g_log.php?log [L,NE,E=7G_USER_AGENT:%1]	
</IfModule>

# 7G:[REMOTE HOST]
<IfModule mod_rewrite.c>	
	RewriteCond %{REQUEST_URI} !(7g_log.php) [NC]	
	RewriteCond %{REMOTE_HOST} (163data|amazonaws|colocrossing|crimea|g00g1e|justhost|kanagawa|loopia|masterhost|onlinehome|poneytel|sprintdatacenter|reverse.softlayer|safenet|ttnet|woodpecker|wowrack) [NC]	
	RewriteRule . - [F,L]	
	# RewriteRule . /7g_log.php?log [L,NE,E=7G_REMOTE_HOST:%1]	
</IfModule>

# 7G:[HTTP REFERRER]
<IfModule mod_rewrite.c>	
	RewriteCond %{REQUEST_URI} !(7g_log.php) [NC]	
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC,OR]
	RewriteCond %{HTTP_REFERER} (ambien|blue\spill|cialis|cocaine|ejaculat|erectile|erections|hoodia|huronriveracres|impotence|levitra|libido|lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby|ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo) [NC]
	RewriteRule . - [F,L]	
	# RewriteRule . /7g_log.php?log [L,NE,E=7G_HTTP_REFERRER:%1]	
</IfModule>

# 7G:[REQUEST METHOD]
<IfModule mod_rewrite.c>	
	RewriteCond %{REQUEST_URI} !(7g_log.php) [NC]	
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|delete|move|put|trace|track) [NC]	
	RewriteRule . - [F,L]	
	# RewriteRule . /7g_log.php?log [L,NE,E=7G_REQUEST_METHOD:%1]	
</IfModule>';

        $rules['wp_firewall_header_caching'] = '## HEADER CACHING AND EXPIRED CONTROLS

#1 Caching Media Files
<FilesMatch "\.(ico|gif|jpg|jpeg|png|flv|pdf|swf|mov|mp3|wmv|ppt)$">
Header set Cache-Control "max-age=2592000"
</FilesMatch>

#2 Caching Graphic File
<FilesMatch "\.(js|css|pdf|swf)$">
Header set Cache-Control "max-age=604800"
</FilesMatch>

#3 Caching Content File
<FilesMatch "\.(html|htm|txt|xml)$">
Header set Cache-Control "max-age=600"
</FilesMatch>

#4 Caching Sistem File
<FilesMatch "\.(pl|php|cgi|spl|scgi|fcgi)$">
Header unset Cache-Control
</FilesMatch>';

        $rules = apply_filters( 'wp-firewall-rules', $rules );

        return $rules;

    }
}