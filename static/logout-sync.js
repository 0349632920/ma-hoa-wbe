// static/logout-sync.js
(function() {
    'use strict';

    // Hàm xử lý khi nhận được tín hiệu logout từ tab khác
    function handleLogoutSignal() {
        console.log("Phát hiện tab khác đăng xuất. Đang tải lại trang...");
        
        // Dừng nhạc nếu đang phát (tránh bị rè)
        try {
            if (window.audio && typeof window.audio.pause === 'function') window.audio.pause();
            const audioElement = document.getElementById('audioElement');
            if (audioElement) audioElement.pause();
        } catch (e) {}

        // Tự động tải lại trang
        window.location.reload();
    }

    // 1. Lắng nghe qua LocalStorage (Dành cho các trình duyệt cũ)
    window.addEventListener('storage', (e) => {
        if (e.key === 'force_logout_event') {
            handleLogoutSignal();
        }
    });

    // 2. Lắng nghe qua BroadcastChannel (Nhanh hơn, độ trễ 0ms)
    if (window.BroadcastChannel) {
        try {
            const bc = new BroadcastChannel('logout_channel');
            bc.onmessage = (event) => {
                if (event.data === 'force_logout') {
                    handleLogoutSignal();
                }
            };
        } catch (e) {}
    }

    // 3. Hàm bắn tín hiệu (Gọi khi bấm nút Đăng xuất)
    window.forceLogoutAllTabs = function() {
        // Gửi qua LocalStorage
        localStorage.setItem('force_logout_event', Date.now().toString());

        // Gửi qua BroadcastChannel
        if (window.BroadcastChannel) {
            try {
                const bc = new BroadcastChannel('logout_channel');
                bc.postMessage('force_logout');
                bc.close();
            } catch (e) {}
        }
    };
})();
