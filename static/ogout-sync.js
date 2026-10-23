// static/logout-sync.js
// Tự động phát hiện logout ở tab khác và hiện GUI

(function() {
    // 1. Tạo GUI Đăng xuất
    function injectLogoutOverlay() {
        if (document.getElementById('globalForcedLogout')) return;

        const overlay = document.createElement('div');
        overlay.id = 'globalForcedLogout';
        overlay.style.cssText = `
            position: fixed; inset: 0; background: rgba(10, 10, 15, 0.9);
            backdrop-filter: blur(10px); z-index: 9999999;
            display: none; justify-content: center; align-items: center;
            font-family: 'Inter', sans-serif;
        `;
        overlay.innerHTML = `
            <div style="background: linear-gradient(135deg, #1a1a2e, #0f0f1a); border: 2px solid #e74c3c; border-radius: 20px; padding: 40px 32px; text-align: center; max-width: 400px; width: 90%; box-shadow: 0 20px 60px rgba(231, 76, 60, 0.3);">
                <div style="font-size: 4rem; margin-bottom: 16px;">🚪</div>
                <h2 style="color: #ff4757; font-size: 1.5rem; margin-bottom: 10px;">Đã đăng xuất</h2>
                <p style="color: #c8c8e0; margin-bottom: 24px; font-size: 0.95rem;">Tài khoản của bạn đã đăng xuất ở một tab khác.</p>
                <button onclick="window.location.href='/login'" style="width: 100%; padding: 14px; border: none; border-radius: 12px; background: linear-gradient(135deg, #ff4757, #c0392b); color: #fff; font-weight: 700; font-size: 1rem; cursor: pointer; font-family: inherit;">
                    🔐 Đăng nhập lại
                </button>
            </div>
        `;
        document.body.appendChild(overlay);
    }

    // 2. Hiện GUI
    window.showForcedLogout = function() {
        injectLogoutOverlay();
        document.getElementById('globalForcedLogout').style.display = 'flex';
        // Dừng nhạc nếu đang phát
        if (window.audio && typeof window.audio.pause === 'function') {
            window.audio.pause();
        }
    };

    // 3. Lắng nghe tín hiệu từ tab khác qua LocalStorage
    window.addEventListener('storage', (e) => {
        if (e.key === 'logout_signal' && e.newValue === 'true') {
            window.showForcedLogout();
        }
    });

    // 4. Lắng nghe tín hiệu qua BroadcastChannel (nhanh hơn)
    if (window.BroadcastChannel) {
        const bc = new BroadcastChannel('logout_channel');
        bc.onmessage = (event) => {
            if (event.data === 'logout') {
                window.showForcedLogout();
            }
        };
    }

    // 5. Ghi đè hàm logout toàn cục để bắn tín hiệu
    window.forceLogoutAllTabs = function() {
        // Bắn tín hiệu qua LocalStorage
        localStorage.setItem('logout_signal', 'true');
        setTimeout(() => localStorage.removeItem('logout_signal'), 1000);

        // Bắn tín hiệu qua BroadcastChannel
        if (window.BroadcastChannel) {
            const bc = new BroadcastChannel('logout_channel');
            bc.postMessage('logout');
            bc.close();
        }
    };
})();
