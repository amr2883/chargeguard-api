<?php
require_once '/var/www/html/wp-load.php';
$user = wp_get_current_user();
echo 'User: ' . $user->user_login . ' | Roles: ' . implode(', ', $user->roles) . PHP_EOL;
echo 'Can manage_woocommerce: ' . (current_user_can('manage_woocommerce') ? 'Yes' : 'No') . PHP_EOL;
global $submenu;
if (isset($submenu['woocommerce'])) {
    echo 'WooCommerce submenu items:' . PHP_EOL;
    foreach ($submenu['woocommerce'] as $item) {
        echo '- ' . $item[0] . ' (slug: ' . $item[2] . ')' . PHP_EOL;
    }
} else {
    echo 'No submenu for woocommerce.' . PHP_EOL;
}
