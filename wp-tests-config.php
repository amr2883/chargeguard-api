<?php
define( 'DB_NAME', 'test' );
define( 'DB_USER', 'test' );
define( 'DB_PASSWORD', 'test' );
define( 'DB_HOST', 'test-db' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
define( 'AUTH_KEY',         'test' );
define( 'SECURE_AUTH_KEY',  'test' );
define( 'LOGGED_IN_KEY',    'test' );
define( 'NONCE_KEY',        'test' );
define( 'AUTH_SALT',        'test' );
define( 'SECURE_AUTH_SALT', 'test' );
define( 'LOGGED_IN_SALT',   'test' );
define( 'NONCE_SALT',       'test' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', true );
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';