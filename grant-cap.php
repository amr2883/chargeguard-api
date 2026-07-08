<?php
require '/var/www/html/wp-load.php';
$user = get_user_by('login', 'admin');
if ($user) {
    $user->add_cap('manage_woocommerce');
    echo 'Done';
} else {
    echo 'User not found';
}
