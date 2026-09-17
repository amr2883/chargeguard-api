# ============================================================
# sync-to-release.ps1
# بينسخ الملفات المتغيرة من woocommerce-chargeguard (source of truth)
# إلى chargeguard-plugin-sync (الريبو اللي بيتنشر منه)، ويعمل commit تلقائي
# ============================================================

$Source = "C:\Users\Future\chargeguard-woocommerce-backend\woocommerce-chargeguard"
$Target = "C:\Users\Future\chargeguard-plugin-sync"

if (-not (Test-Path $Source)) { throw "Source path not found: $Source" }
if (-not (Test-Path $Target)) { throw "Target path not found: $Target" }

Write-Host "=== نسخ الملفات من Source إلى plugin-sync ===" -ForegroundColor Cyan

robocopy $Source $Target /E /XD .git vendor jscpd-php-report node_modules build /XF hash1.txt hash2.txt /NFL /NDL /NJH

Write-Host "`n=== حالة الريبو بعد النسخ ===" -ForegroundColor Cyan
Push-Location $Target
git status --short

$hasChanges = (git status --porcelain)
if ($hasChanges) {
    Write-Host "`n=== فيه تغييرات — هل تحب تعمل commit؟ (y/n) ===" -ForegroundColor Yellow
    $confirm = Read-Host
    if ($confirm -eq 'y') {
        git add -A
        $msg = Read-Host "اكتب رسالة الكوميت (مثال: sync: bring plugin up to date with source-of-truth)"
        git commit -m "$msg"
        Write-Host "`nتم الـ commit. لو عايز تنشر إصدار جديد دلوقتي، اعمل tag ودفعه:" -ForegroundColor Green
        Write-Host "  git tag v1.0.26" -ForegroundColor Gray
        Write-Host "  git push origin main --tags" -ForegroundColor Gray
    } else {
        Write-Host "اتلغى الـ commit — الملفات اتنسخت بس من غير commit." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nمفيش تغييرات — plugin-sync متزامن بالفعل مع المصدر." -ForegroundColor Green
}
Pop-Location
