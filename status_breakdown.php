<?php
$orders = wc_get_orders(['limit' => 200, 'orderby' => 'date', 'order' => 'DESC']);
$statuses = [];
foreach ($orders as $order) {
    $s = $order->get_status();
    $statuses[$s] = ($statuses[$s] ?? 0) + 1;
    if ($order->get_date_created()) {
        // نطبع أقدم وأحدث تاريخ لكل حالة عشان نعرف المدى الزمني
    }
}
foreach ($statuses as $status => $count) {
    echo "$status => $count\n";
}
echo "---\n";
echo "Oldest order date: " . $orders[count($orders)-1]->get_date_created()->date('Y-m-d H:i:s') . "\n";
echo "Newest order date: " . $orders[0]->get_date_created()->date('Y-m-d H:i:s') . "\n";
