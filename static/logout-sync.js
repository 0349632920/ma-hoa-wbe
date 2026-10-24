// static/logout-sync.js
(function() {
    'use strict';

    // ==========================================
    // 1. TẠO GIAO DIỆN (GUI) BÁO LỖI ĐĂNG XUẤT
    // ==========================================
    function injectLogoutOverlay() {
        if (document.getElementById('globalForcedLogout')) return;

        const overlay = document.createElement('div');
        overlay.id = 'globalForcedLogout';
        overlay.style.cssText = `
            position: fixed; inset: 0; background: rgba(10, 10, 15, 0.9);
            backdrop-filter: blur(10px); z-index: 9999999;
            display: none; justify-content: center; align-items: center;
            font-family: 'Inter', 'Segoe UI', Roboto, sans-serif;
        `;
        overlay.innerHTML = `
            <div style="background: linear-gradient(135deg, #1a1a2e, #0f0f1a); border: 2px solid #e74c3c; border-radius: 20px; padding: 40px 32px; text-align: center; max-width: 400px; width: 90%; box-shadow: 0 20px 60px rgba(231, 76, 60, 0.3);">
                <div style="font-size: 4rem; margin-bottom: 16px; animation: pulseLogout 2s infinite;">🚪</div>
                <h2 style="color: #ff4757; font-size: 1.5rem; margin-bottom: 10px;">Phiên đăng nhập hết hạn</h2>
                <p style="color: #c8c8e0; margin-bottom: 24px; font-size: 0.95rem; line-height: 1.5;">
                    Tài khoản của bạn đã đăng xuất hoặc phiên làm việc đã kết thúc.<br>Vui lòng đăng nhập lại để tiếp tục sử dụng.
                </p>
                <button onclick="window.location.href='/login'" style="width: 100%; padding: 14px; border: none; border-radius: 12px; background: linear-gradient(135deg, #ff4757, #c0392b); color: #fff; font-weight: 700; font-size: 1rem; cursor: pointer; font-family: inherit; transition: all 0.2s;" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'">
                    🔐 Đăng nhập lại
                </button>
            </div>
            <style>
                @keyframes pulseLogout {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
            </style>
        `;
        document.body.appendChild(overlay);
    }

    // ==========================================
    // 2. HÀM HIỂN THỊ GUI VÀ KHÓA WEB
    // ==========================================
    let isLoggingOut = false;
    
    window.showForcedLogout = function() {
        if (isLoggingOut) return; // Tránh hiện nhiều lần
        isLoggingOut = true;

        injectLogoutOverlay();
        const overlay = document.getElementById('globalForcedLogout');
        if (overlay) overlay.style.display = 'flex';

        // Dừng nhạc nếu đang phát
        try {
            if (window.audio && typeof window.audio.pause === 'function') window.audio.pause();
            const audioElement = document.getElementById('audioElement');
            if (audioElement) audioElement.pause();
        } catch (e) {}

        // Dừng mọi tiến trình chạy ngầm (Polling)
        try {
            if (typeof window.stopPolling === 'function') window.stopPolling();
            if (typeof window.stopGameBanPolling === 'function') window.stopGameBanPolling();
        } catch (e) {}
    };

    // ==========================================
    // 3. ĐÁNH CHẶN MỌI FETCH REQUEST (QUAN TRỌNG)
    // ==========================================
    // Nếu bất kỳ tính năng nào (Vòng quay, Chat, Viết văn...) gửi request 
    // mà Server trả về 401 (Hết phiên) -> Tự động hiện GUI
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        try {
            const response = await originalFetch.apply(this, args);
            
            // Nếu Server báo 401 Unauthorized (Chưa đăng nhập)
            if (response.status === 401 && !args[0].includes('/login')) {
                window.showForcedLogout();
                // Ném lỗi để code bên dưới dừng chạy (không bị lỗi ngầm)
                throw new Error("Unauthorized - Session expired");
            }
            return response;
        } catch (error) {
            // Nếu mất mạng hoặc lỗi, ném lỗi ra ngoài
            throw error;
        }
    };

    // ==========================================
    // 4. LẮNG NGHE TÍN HIỆU TỪ TAB KHÁC
    // ==========================================
    window.addEventListener('storage', (e) => {
        if (e.key === 'force_logout_event') {
            window.showForcedLogout();
        }
    });

    if (window.BroadcastChannel) {
        try {
            const bc = new BroadcastChannel('logout_channel');
            bc.onmessage = (event) => {
                if (event.data === 'force_logout') {
                    window.showForcedLogout();
                }
            };
        } catch (e) {}
    }

    // ==========================================
    // 5. HÀM GỬI TÍN HIỆU (Gọi khi bấm Logout)
    // ==========================================
    window.forceLogoutAllTabs = function() {
        localStorage.setItem('force_logout_event', Date.now().toString());
        if (window.BroadcastChannel) {
            try {
                const bc = new BroadcastChannel('logout_channel');
                bc.postMessage('force_logout');
                bc.close();
            } catch (e) {}
        }
    };

})();
