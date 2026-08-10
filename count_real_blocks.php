<?php
$orders = wc_get_orders(['limit' => 200, 'orderby' => 'date', 'order' => 'DESC']);
$total = count($orders);
$blocked = 0;
foreach ($orders as $order) {
    $reason = $order->get_meta('_chargeguard_block_reason');
    if (!empty($reason)) {
        $blocked++;
        echo "ID=" . $order->get_id() . " reason=" . $reason . "\n";
    }
}
echo "---\nTotal orders scanned: $total | Blocked with reason: $blocked\n";
