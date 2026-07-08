<?php
require_once '/var/www/html/wp-load.php';
$admin_role = get_role('administrator');
if ($admin_role) {
    $admin_role->add_cap('manage_woocommerce');
    echo 'Success: manage_woocommerce capability added.';
} else {
    echo 'Error: Administrator role not found.';
}