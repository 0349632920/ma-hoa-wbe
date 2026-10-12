/**
 * game_polling.js — Polling cho trang game
 * - Kiểm tra cấm game mỗi 3 giây
 * - Nếu bị cấm → hiện thông báo → chuyển sang /game
 * - Nếu được gỡ cấm → hiện "đã gỡ ban" → tắt
 */
(function() {
    'use strict';

    const POLL_INTERVAL = 3000;
    let pollTimer = null;
    let isPolling = false;
    let wasGameBanned = false;
    let isHandling = false;

    // ═══════════════════════════════════════
    // TẠO NOTIFICATION "ĐÃ GỠ BAN"
    // ═══════════════════════════════════════
    function ensureUnbanNotification() {
        if (document.getElementById('__unbanNotify')) return;

        const style = document.createElement('style');
        style.textContent = `
            #__unbanNotify {
                position: fixed;
                top: 20px;
                left: 50%;
                transform: translateX(-50%) translateY(-150%);
                z-index: 99999;
                background: linear-gradient(135deg, #27ae60, #16a085);
                color: #fff;
                padding: 16px 28px;
                border-radius: 16px;
                box-shadow: 0 15px 50px rgba(39, 174, 96, 0.5);
                font-family: 'Inter', 'Segoe UI', sans-serif;
                font-weight: 700;
                font-size: 1rem;
                display: flex;
                align-items: center;
                gap: 14px;
                transition: transform 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
                max-width: 90vw;
                border: 2px solid rgba(255, 255, 255, 0.3);
            }
            #__unbanNotify.show {
                transform: translateX(-50%) translateY(0);
            }
            #__unbanNotify .__icon {
                font-size: 1.8rem;
                animation: __unbanBounce 0.6s ease infinite alternate;
            }
            @keyframes __unbanBounce {
                from { transform: scale(1); }
                to   { transform: scale(1.15); }
            }
            #__unbanNotify .__text small {
                display: block;
                font-weight: 500;
                font-size: 0.82rem;
                opacity: 0.9;
                margin-top: 2px;
            }
            #__unbanNotify .__progress {
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
                border-radius: 0 0 16px 16px;
                overflow: hidden;
            }
            #__unbanNotify .__progress-fill {
                height: 100%;
                background: #fff;
                animation: __unbanProgress 2.5s linear forwards;
            }
            @keyframes __unbanProgress {
                from { width: 0%; }
                to   { width: 100%; }
            }
        `;
        document.head.appendChild(style);

        const notif = document.createElement('div');
        notif.id = '__unbanNotify';
        notif.innerHTML = `
            <div class="__icon">🎉</div>
            <div class="__text">
                <strong>Bạn đã được gỡ cấm chơi game!</strong>
                <small>Đang tải lại trang...</small>
            </div>
            <div class="__progress"><div class="__progress-fill"></div></div>
        `;
        document.body.appendChild(notif);
    }

    // ═══════════════════════════════════════
    // SHOW / HIDE
    // ═══════════════════════════════════════
    function showUnbanNotify() {
        ensureUnbanNotification();
        const notif = document.getElementById('__unbanNotify');
        notif.classList.add('show');
    }

    // ═══════════════════════════════════════
    // POLLING
    // ═══════════════════════════════════════
    async function poll() {
        if (isHandling) return;
        if (isPolling) return;
        if (document.hidden) return;

        isPolling = true;
        try {
            const res = await fetch('/api/game/check-ban', {
                headers: { 'Cache-Control': 'no-cache' },
                credentials: 'same-origin'
            });

            if (res.status === 401) {
                stopPolling();
                window.location.href = '/login';
                return;
            }

            const data = await res.json();

            // ═══ BAN TÀI KHOẢN ═══
            if (data.account_banned) {
                isHandling = true;
                stopPolling();
                window.location.href = data.redirect || '/banned';
                return;
            }

            // ═══ PENDING DELETE ═══
            if (data.pending_delete) {
                isHandling = true;
                stopPolling();
                window.location.href = data.redirect || '/deleted';
                return;
            }

            // ═══ CẤM GAME ═══
            if (data.is_banned) {
                wasGameBanned = true;
                isHandling = true;
                stopPolling();
                // Chuyển sang /game để hiện game_banned.html
                if (window.location.pathname !== '/game') {
                    window.location.href = '/game';
                }
                return;
            }

            // ═══ ĐƯỢC GỠ CẤM GAME ═══
            if (wasGameBanned && !data.is_banned) {
                wasGameBanned = false;
                isHandling = true;
                stopPolling();
                showUnbanNotify();

                // Reload sau 2.5 giây
                setTimeout(() => {
                    window.location.href = '/game';
                }, 2500);
                return;
            }

        } catch (e) {
            // Silent fail — không làm phiền user
        } finally {
            isPolling = false;
        }
    }

    function startPolling() {
        if (pollTimer) clearInterval(pollTimer);
        setTimeout(poll, 1500);
        pollTimer = setInterval(poll, POLL_INTERVAL);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && !isHandling) {
            poll();
        }
    });

    window.addEventListener('beforeunload', stopPolling);

    // ═══════════════════════════════════════
    // INIT
    // ═══════════════════════════════════════
    function init() {
        ensureUnbanNotification();
        startPolling();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
