// ============================================================
// STATE
// ============================================================
let state = {
    mode: "encode",
    algo: "base64",
    algoLabel: "📦 Base64",
    algos: null,
    isLoggedIn: false,
    isAdmin: false,
    isBanned: false,
    loginChecked: false,
};

// ============================================================
// KHỞI TẠO
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
    await checkLogin();
    await loadAlgos();
    bindEvents();
    initUserMenu();
    initErrorToast();
});

// ============================================================
// CHECK LOGIN — có timeout 5s
// ============================================================
async function checkLogin() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const res = await fetch("/api/me", {
            credentials: "include",
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        const data = await res.json();
        state.isLoggedIn = data.logged_in;
        state.isAdmin = data.is_admin || false;
        state.isBanned = data.is_banned || false;
        state.loginChecked = true;

        if (state.isLoggedIn && state.isBanned) {
            window.location.href = "/banned";
        }
    } catch (e) {
        console.error("Lỗi check login:", e);
        state.isLoggedIn = false;
        state.isAdmin = false;
        state.loginChecked = true;
    }
}

async function ensureLogin() {
    if (state.loginChecked) return state.isLoggedIn;
    try {
        await Promise.race([
            checkLogin(),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error("timeout")), 5000)
            )
        ]);
    } catch (e) {
        console.error("ensureLogin timeout:", e);
        state.loginChecked = true;
    }
    return state.isLoggedIn;
}

async function loadAlgos() {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);

        const res = await fetch("/api/algos", {
            credentials: "include",
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        const data = await res.json();
        state.algos = data;
        document.getElementById("algo-count").textContent = data.total;
    } catch (e) {
        console.error("Lỗi load algos:", e);
        // Fallback: dùng danh sách mặc định nếu API lỗi
        state.algos = {
            grouped: {
                "Cơ bản": [
                    { key: "base64", label: "📦 Base64" },
                    { key: "base32", label: "🗜 Base32" },
                    { key: "hex", label: "#️⃣ Hex" },
                    { key: "binary", label: "🔢 Nhị phân" },
                ],
                "Cổ điển": [
                    { key: "rot13", label: "🔄 ROT13" },
                    { key: "caesar", label: "🏛 Caesar" },
                ],
                "Ký tự": [
                    { key: "morse", label: "📡 Morse" },
                    { key: "unicode", label: "🌐 Unicode" },
                ],
                "Bảo mật": [
                    { key: "aes", label: "🔐 AES-256" },
                ],
            },
            order: ["Cơ bản", "Cổ điển", "Ký tự", "Bảo mật"],
            total: 9,
        };
        document.getElementById("algo-count").textContent = state.algos.total;
    }
}

// ============================================================
// BIND EVENTS
// ============================================================
function bindEvents() {
    document.querySelectorAll(".toggle-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const newMode = btn.dataset.mode;
            if (newMode === state.mode) return;
            switchMode(newMode);
        });
    });

    document.getElementById("algo-picker").addEventListener("click", openModal);
    document.getElementById("close-modal").addEventListener("click", closeModal);
    document.getElementById("algo-modal").addEventListener("click", (e) => {
        if (e.target.id === "algo-modal") closeModal();
    });

    document.getElementById("search").addEventListener("input", (e) => {
        renderAlgoList(e.target.value.toLowerCase());
    });

    document.getElementById("toggle-key").addEventListener("click", () => {
        const inp = document.getElementById("key");
        const btn = document.getElementById("toggle-key");
        if (inp.type === "password") {
            inp.type = "text";
            btn.textContent = "🙈";
        } else {
            inp.type = "password";
            btn.textContent = "👁";
        }
    });

    document.getElementById("btn-run").addEventListener("click", runProcess);

    document.getElementById("btn-swap").addEventListener("click", () => {
        const inp = document.getElementById("input");
        const out = document.getElementById("output");
        inp.value = out.value;
        out.value = "";
        updateCount();
    });

    document.getElementById("btn-clear").addEventListener("click", () => {
        document.getElementById("input").value = "";
        document.getElementById("output").value = "";
        updateCount();
    });

    document.getElementById("copy-out").addEventListener("click", () => {
        const out = document.getElementById("output");
        if (out.value) {
            navigator.clipboard.writeText(out.value);
            showToast("✅ Đã sao chép!");
        }
    });

    document.getElementById("input").addEventListener("input", updateCount);

    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            runProcess();
        }
        if (e.key === "Escape") closeModal();
    });
}

function updateCount() {
    const t = document.getElementById("input").value;
    document.getElementById("count-in").textContent = `${t.length} ký tự`;
}

// ============================================================
// SWITCH MODE
// ============================================================
function switchMode(newMode) {
    const slider = document.getElementById("transition-slider");
    const sliderBg = document.getElementById("slider-bg");
    const sliderIcon = document.getElementById("slider-icon");
    const sliderText = document.getElementById("slider-text");
    const sliderSubtext = document.getElementById("slider-subtext");
    const main = document.querySelector(".main");

    if (newMode === "decode") {
        sliderBg.classList.add("green");
        sliderIcon.textContent = "🔓";
        sliderText.textContent = "GIẢI MÃ";
        sliderSubtext.textContent = "Đang chuyển sang chế độ giải mã...";
    } else {
        sliderBg.classList.remove("green");
        sliderIcon.textContent = "🔒";
        sliderText.textContent = "MÃ HÓA";
        sliderSubtext.textContent = "Đang chuyển sang chế độ mã hóa...";
    }

    slider.classList.remove("active");
    void slider.offsetWidth;
    slider.classList.add("active");

    setTimeout(() => {
        state.mode = newMode;

        document.querySelectorAll(".toggle-btn").forEach(b => {
            b.classList.toggle("active", b.dataset.mode === newMode);
        });

        document.getElementById("btn-run-text").textContent =
            newMode === "encode" ? "⚙ MÃ HÓA" : "🔓 GIẢI MÃ";

        document.body.classList.toggle("decode-mode", newMode === "decode");

        document.getElementById("input").placeholder =
            newMode === "encode"
                ? "Nhập văn bản cần mã hóa..."
                : "Dán nội dung cần giải mã vào đây...";

        const titles = document.querySelectorAll(".panel-title");
        if (newMode === "encode") {
            titles[0].textContent = "Văn bản gốc";
            titles[1].textContent = "Kết quả";
        } else {
            titles[0].textContent = "Văn bản đã mã hóa";
            titles[1].textContent = "Kết quả giải mã";
        }

        main.classList.add("switching");
        setTimeout(() => main.classList.remove("switching"), 800);

        const inp = document.getElementById("input");
        const out = document.getElementById("output");
        if (out.value && !inp.value) {
            inp.value = out.value;
            out.value = "";
            updateCount();
        }
    }, 400);

    setTimeout(() => {
        slider.classList.remove("active");
    }, 800);
}

// ============================================================
// MODAL CHỌN THUẬT TOÁN
// ============================================================
function openModal() {
    document.getElementById("algo-modal").classList.add("show");
    renderAlgoList("");
    setTimeout(() => document.getElementById("search").focus(), 100);
}

function closeModal() {
    document.getElementById("algo-modal").classList.remove("show");
    document.getElementById("search").value = "";
}

function renderAlgoList(query) {
    const container = document.getElementById("algo-list");
    container.innerHTML = "";
    if (!state.algos) return;

    const { grouped, order } = state.algos;

    for (const group of order) {
        if (!grouped[group]) continue;
        const filtered = grouped[group].filter(a =>
            a.label.toLowerCase().includes(query) ||
            a.key.toLowerCase().includes(query)
        );
        if (filtered.length === 0) continue;

        const title = document.createElement("div");
        title.className = "algo-group-title";
        title.textContent = group.toUpperCase();
        container.appendChild(title);

        const grid = document.createElement("div");
        grid.className = "algo-grid";

        for (const algo of filtered) {
            const item = document.createElement("div");
            item.className = "algo-item" + (algo.key === state.algo ? " active" : "");
            item.textContent = algo.label;
            item.addEventListener("click", () => {
                state.algo = algo.key;
                state.algoLabel = algo.label;
                document.getElementById("current-algo").textContent = algo.label;
                closeModal();
            });
            grid.appendChild(item);
        }
        container.appendChild(grid);
    }

    if (container.children.length === 0) {
        container.innerHTML = `<p style="text-align:center;color:#7a9bc4;padding:40px 0;">❌ Không tìm thấy thuật toán nào</p>`;
    }
}

// ============================================================
// RUN PROCESS — có timeout, không bao giờ treo
// ============================================================
async function runProcess() {
    const text = document.getElementById("input").value;
    const key = document.getElementById("key").value;
    const btn = document.getElementById("btn-run");

    if (!text) {
        showToast("⚠ Chưa nhập văn bản!", true);
        return;
    }

    // Lưu text gốc của nút
    const originalText = document.getElementById("btn-run-text").textContent;

    // Hiện loading NGAY
    btn.disabled = true;
    document.getElementById("btn-run-text").innerHTML =
        `<span class="loading"></span> Đang xử lý...`;

    try {
        // ===== Kiểm tra login với timeout 5s =====
        let loggedIn = false;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const meRes = await fetch("/api/me", {
                credentials: "include",
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            const meData = await meRes.json();
            loggedIn = meData.logged_in;
            state.isLoggedIn = loggedIn;
            state.isAdmin = meData.is_admin || false;
            state.loginChecked = true;

            // Nếu bị ban → chuyển đến trang banned
            if (meData.is_banned) {
                window.location.href = "/banned";
                return;
            }
        } catch (e) {
            console.error("Lỗi check login:", e);
            loggedIn = state.isLoggedIn;
        }

        // Nếu chưa login → hiện modal
        if (!loggedIn) {
            btn.disabled = false;
            document.getElementById("btn-run-text").textContent = originalText;
            openLoginRequiredModal();
            return;
        }

        // ===== Gọi API process với timeout 15s =====
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);

        let res;
        try {
            res = await fetch("/api/process", {
                method: "POST",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    mode: state.mode,
                    algo: state.algo,
                    text: text,
                    key: key,
                }),
                signal: controller.signal
            });
        } finally {
            clearTimeout(timeoutId);
        }

        // Session hết hạn
        if (res.status === 401) {
            btn.disabled = false;
            document.getElementById("btn-run-text").textContent = originalText;
            state.loginChecked = false;
            openLoginRequiredModal();
            return;
        }

        // Bị cấm
        if (res.status === 403) {
            const data = await res.json();
            if (data.banned) {
                window.location.href = "/banned";
                return;
            }
            showToast(`❌ ${data.error || "Không có quyền"}`, true);
            return;
        }

        const data = await res.json();

        if (data.success) {
            document.getElementById("output").value = data.result;
            showToast(`✅ ${state.mode === "encode" ? "Mã hóa" : "Giải mã"} thành công!`);
        } else {
            showToast(`❌ ${data.error}`, true);
        }

    } catch (e) {
        if (e.name === "AbortError") {
            showToast("⏱ Server không phản hồi sau 15 giây. Vui lòng thử lại!", true);
        } else {
            showToast(`❌ Lỗi: ${e.message}`, true);
        }
        console.error("runProcess error:", e);
    } finally {
        // ===== LUÔN LUÔN RESET NÚT =====
        btn.disabled = false;
        document.getElementById("btn-run-text").textContent = originalText;
    }
}

// ============================================================
// TOAST
// ============================================================
let toastTimer = null;
function showToast(msg, isError = false) {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.classList.toggle("error", isError);
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2500);
}

// ============================================================
// LOGIN REQUIRED MODAL
// ============================================================
function openLoginRequiredModal() {
    const modal = document.getElementById("login-required-modal");
    if (modal) modal.classList.add("show");
}

function closeLoginRequiredModal() {
    const modal = document.getElementById("login-required-modal");
    if (modal) modal.classList.remove("show");
}

// ============================================================
// ERROR TOAST (không có quyền)
// ============================================================
function initErrorToast() {
    const errorToast = document.getElementById("error-toast");
    if (errorToast) {
        setTimeout(() => {
            errorToast.classList.add("show");
        }, 100);
        setTimeout(() => {
            errorToast.classList.remove("show");
            setTimeout(() => {
                if (errorToast.parentNode) errorToast.remove();
            }, 300);
        }, 4000);
    }
}

// ============================================================
// USER MENU
// ============================================================
async function initUserMenu() {
    // Avatar
    const nameEl = document.getElementById("user-name");
    const avatarEl = document.getElementById("user-avatar");
    if (nameEl && avatarEl) {
        const name = nameEl.textContent.trim();
        avatarEl.textContent = name.charAt(0).toUpperCase();
    }

    // Nút đăng nhập ở top (nếu là khách)
    const topLoginBtn = document.getElementById("btn-top-login");
    if (topLoginBtn) {
        topLoginBtn.addEventListener("click", () => {
            window.location.href = "/login";
        });
    }

    // ===== NÚT ADMIN =====
    const adminBtn = document.getElementById("btn-admin");
    if (adminBtn && state.isAdmin) {
        adminBtn.style.display = "flex";
        adminBtn.addEventListener("click", () => {
            window.location.href = "/admin";
        });
    }

    // ===== MODAL ĐĂNG XUẤT =====
    const logoutModal = document.getElementById("logout-modal");
    const confirmUsername = document.getElementById("confirm-username");
    const logoutBtn = document.getElementById("btn-logout");
    const cancelBtn = document.getElementById("btn-cancel-logout");
    const confirmBtn = document.getElementById("btn-confirm-logout");

    function openLogoutModal() {
        const name = nameEl ? nameEl.textContent.trim() : "bạn";
        if (confirmUsername) confirmUsername.textContent = name;
        if (logoutModal) logoutModal.classList.add("show");
        if (cancelBtn) setTimeout(() => cancelBtn.focus(), 100);
    }

    function closeLogoutModal() {
        if (logoutModal) logoutModal.classList.remove("show");
    }

    async function doLogout() {
        if (confirmBtn) {
            confirmBtn.disabled = true;
            confirmBtn.textContent = "⏳ Đang thoát...";
        }
        try {
            await fetch("/api/logout", { method: "POST", credentials: "include" });
            window.location.href = "/";
        } catch (e) {
            alert("Lỗi đăng xuất");
            if (confirmBtn) {
                confirmBtn.disabled = false;
                confirmBtn.textContent = "Đăng xuất";
            }
        }
    }

    if (logoutBtn) logoutBtn.addEventListener("click", openLogoutModal);
    if (cancelBtn) cancelBtn.addEventListener("click", closeLogoutModal);
    if (confirmBtn) confirmBtn.addEventListener("click", doLogout);
    if (logoutModal) {
        logoutModal.addEventListener("click", (e) => {
            if (e.target === logoutModal) closeLogoutModal();
        });
    }

    // ===== MODAL YÊU CẦU ĐĂNG NHẬP =====
    const loginRequiredModal = document.getElementById("login-required-modal");
    const cancelLoginBtn = document.getElementById("btn-cancel-login");
    const goLoginBtn = document.getElementById("btn-go-login");

    if (cancelLoginBtn) {
        cancelLoginBtn.addEventListener("click", closeLoginRequiredModal);
    }
    if (goLoginBtn) {
        goLoginBtn.addEventListener("click", () => {
            window.location.href = "/login";
        });
    }
    if (loginRequiredModal) {
        loginRequiredModal.addEventListener("click", (e) => {
            if (e.target === loginRequiredModal) closeLoginRequiredModal();
        });
    }

    // Esc đóng modal
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            if (logoutModal && logoutModal.classList.contains("show")) closeLogoutModal();
            if (loginRequiredModal && loginRequiredModal.classList.contains("show")) {
                closeLoginRequiredModal();
            }
        }
    });
}
// ============================================================
// ACCOUNT DELETED OVERLAY
// ============================================================
function showAccountDeletedScreen(username, deletedBy) {
    if (document.getElementById("account-deleted-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "account-deleted-overlay";
    overlay.className = "account-deleted-overlay";
    overlay.innerHTML = `
        <div class="account-deleted-card">
            <div class="account-deleted-icon">🗑</div>
            <h1 class="account-deleted-title">TÀI KHOẢN ĐÃ BỊ XÓA</h1>
            <p class="account-deleted-text">
                Tài khoản <b>${username || "của bạn"}</b> đã bị xóa
                bởi quản trị viên <b>${deletedBy || "Admin"}</b>.
            </p>
            <p class="account-deleted-text">
                Bạn sẽ được chuyển về trang đăng nhập sau
                <b><span id="deleted-countdown">5</span></b> giây...
            </p>
        </div>
    `;
    document.body.appendChild(overlay);

    let countdown = 5;
    const countdownEl = document.getElementById("deleted-countdown");

    const interval = setInterval(() => {
        countdown--;
        if (countdownEl) countdownEl.textContent = countdown;

        if (countdown <= 0) {
            clearInterval(interval);
            window.location.href = "/login";
        }
    }, 1000);
}

// ============================================================
// POLLING — kiểm tra tài khoản còn tồn tại không
// ============================================================
(function startAccountCheck() {
    // Chỉ chạy khi đã login (không phải khách)
    setTimeout(async () => {
        try {
            const meRes = await fetch("/api/me", { credentials: "include" });
            const meData = await meRes.json();

            if (!meData.logged_in) return;

            // Bắt đầu polling
            setInterval(async () => {
                try {
                    const res = await fetch("/api/check-user-exists", {
                        credentials: "include"
                    });
                    const data = await res.json();

                    if (data.deleted) {
                        showAccountDeletedScreen(
                            data.username,
                            data.deleted_by
                        );
                    }
                } catch (e) {}
            }, 5000);

        } catch (e) {}
    }, 2000);
})();
