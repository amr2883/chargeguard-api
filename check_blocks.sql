SELECT p.ID, p.post_status, pm.meta_value AS block_reason
FROM wp_posts p
JOIN wp_postmeta pm ON p.ID = pm.post_id
WHERE pm.meta_key = '_chargeguard_block_reason'
ORDER BY p.ID DESC
LIMIT 20;
