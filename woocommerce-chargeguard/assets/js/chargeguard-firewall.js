/**
 * ChargeGuard Device Fingerprint – JavaScript خفيف بدون تبعيات خارجية.
 *
 * - يحسب بصمة جهاز من خصائص المتصفح العامة
 * - يحفظها في كوكي الجلسة
 * - يستعلم من الخادم Ajax لفحص الحظر
 * - إذا حُظر، يمنع الوصول إلى الدفع ويعرض رسالة
 *
 * @since 1.0.0
 */

(function($) {
    'use strict';

    /**
     * توليد بصمة بسيطة من خصائص المتصفح.
     * @return {string} بصمة فريدة (نسبياً) تبدأ بـ "fp_"
     */
    function generateFingerprint() {
        var nav = window.navigator;
        var screen = window.screen;
        var canvas = getCanvasFingerprint();

        var components = [
            nav.userAgent,
            nav.language,
            screen.colorDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset(),
            canvas
        ];

        // دمج المكونات وفصلها بفاصل نادر
        var raw = components.join('###');

        // دالة هاش بسيطة (djb2)
        var hash = 0;
        for (var i = 0; i < raw.length; i++) {
            var char = raw.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0; // Convert to 32bit integer
        }

        return 'fp_' + Math.abs(hash).toString(16);
    }

    /**
     * محاولة توليد بصمة Canvas (إذا كان مدعوماً).
     * @return {string} هيكس رمز canvas فريد نسبياً.
     */
    function getCanvasFingerprint() {
        try {
            var canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(10, 5, 50, 40);   // خلفية ملونة
            ctx.fillStyle = '#069';
            ctx.fillText('ChargeGuard', 20, 20); // نص
            var dataURI = canvas.toDataURL();
            return dataURI.substring(dataURI.length - 50); // آخر 50 حرف كمميز
        } catch (e) {
            return 'canvas_na';
        }
    }

    $(document).ready(function() {
        var fp = generateFingerprint();

        // حفظ البصمة في كوكي للجلسة
        document.cookie = 'chargeguard_fp=' + fp + '; path=/; SameSite=Lax';

        // إعلام الخادم وفحص الحظر
        $.post(chargeguard_fw.ajax_url, {
            action: 'chargeguard_check_fp',
            fingerprint: fp,
            nonce: chargeguard_fw.nonce
        }, function(response) {
            if (response.success && response.data.blocked) {
                // عرض رسالة واضحة بدلاً من نموذج الدفع
                var checkoutForm = $('form.checkout');
                if (checkoutForm.length) {
                    var message = '<div class="woocommerce-error" style="padding:20px; text-align:center; font-size:1.2em;">' +
                        'عذراً، لا يمكن معالجة طلبك حالياً. يرجى التواصل مع الدعم.' +
                        '</div>';
                    checkoutForm.replaceWith(message);
                }
            }
        }).fail(function() {
            // الفشل في الاتصال = لا نوقف التدفق (منعاً للإيجابيات الخاطئة)
        });
    });
})(jQuery);