<?php
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
deactivate_plugins('chargeguard/chargeguard-woocommerce.php');
activate_plugins('chargeguard/chargeguard-woocommerce.php');
echo 'Re-activated';
