<?php
$fp = "fp2_c2a572c24136abb13546f319b099318079576d5fa0c08e8f75c90437df47caa0";
update_option("chargeguard_device_blacklist", [$fp => time() + 3600]);
echo "Blacklisted: " . $fp . "\n";
