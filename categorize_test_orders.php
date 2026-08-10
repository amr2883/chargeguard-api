<?php
$orders = wc_get_orders(['status' => 'failed', 'limit' => 200]);
$categories = ['velocity' => 0, 'clean' => 0, 'other' => 0];
$velocity_with_reason = 0;
$clean_with_reason = 0;

foreach ($orders as $order) {
    $fp = $order->get_meta('_chargeguard_device_fp');
    $reason = $order->get_meta('_chargeguard_block_reason');
    $risk_score = $order->get_meta('_chargeguard_risk_score');

    if (empty($fp)) continue;

    if (strpos($fp, 'velocity') !== false) {
        $categories['velocity']++;
        if (!empty($reason)) $velocity_with_reason++;
    } elseif (strpos($fp, 'clean') !== false) {
        $categories['clean']++;
        if (!empty($reason)) $clean_with_reason++;
    } else {
        $categories['other']++;
    }
}

echo "Velocity-tagged orders: {$categories['velocity']} (with block_reason: $velocity_with_reason)\n";
echo "Clean-tagged orders: {$categories['clean']} (with block_reason: $clean_with_reason)\n";
echo "Other: {$categories['other']}\n";

// نطبع كل حقول chargeguard الموجودة فعليًا على أول طلب velocity كنموذج
foreach ($orders as $order) {
    $fp = $order->get_meta('_chargeguard_device_fp');
    if (strpos($fp, 'velocity') !== false) {
        echo "--- Sample meta for order #" . $order->get_id() . " ---\n";
        foreach ($order->get_meta_data() as $m) {
            if (strpos($m->key, 'chargeguard') !== false) {
                echo $m->key . " = " . print_r($m->value, true) . "\n";
            }
        }
        break;
    }
}
