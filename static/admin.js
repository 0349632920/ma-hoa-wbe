// ============================================================
// STATE
// ============================================================
let adminState = {
    users: [],
    history: [],
    currentTab: "users",
    confirmCallback: null,
};

// ============================================================
// KHỞI TẠO
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
    await loadStats();
    await loadUsers();
    await loadHistory();
    bindEvents();
    initAvatar();
});

function initAvatar() {
    const nameEl = document.querySelector(".user-name");
    const avatarEl = document.getElementById("user-avatar");
    if (nameEl && avatarEl) {
        avatarEl.textContent = nameEl.textContent.trim().charAt(0).toUpperCase();
    }
}

// ============================================================
// BIND EVENTS
// ============================================================
function bindEvents() {
    // Tabs
    document.querySelectorAll(".admin-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            const target = tab.dataset.tab;
            adminState.currentTab = target;

            document.querySelectorAll(".admin-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            document.getElementById("tab-users").classList.toggle("hidden", target !== "users");
            document.getElementById("tab-history").classList.toggle("hidden", target !== "history");
        });
    });

    // User search
    document.getElementById("user-search").addEventListener("input", (e) => {
        filterUsers(e.target.value.toLowerCase());
    });

    // History search
    document.getElementById("history-search").addEventListener("input", () => {
        loadHistory();
    });

    // History mode
    document.getElementById("history-mode").addEventListener("change", () => {
        loadHistory();
    });

    // Refresh buttons
    document.getElementById("btn-refresh-users").addEventListener("click", loadUsers);
    document.getElementById("btn-refresh-history").addEventListener("click", loadHistory);
    document.getElementById("btn-clear-history").addEventListener("click", () => {
        showConfirm("🗑 Xóa hết lịch sử?", "Toàn bộ lịch sử mã hóa của tất cả users sẽ bị xóa. Không thể hoàn tác!", async () => {
            try {
                const res = await fetch("/api/admin/history/clear", {
                    method: "POST",
                    credentials: "include"
                });
                if (res.ok) {
                    showToast("✅ Đã xóa toàn bộ lịch sử");
                    loadHistory();
                    loadStats();
                } else {
                    showToast("❌ Lỗi xóa lịch sử", true);
                }
            } catch (e) {
                showToast("❌ Lỗi kết nối", true);
            }
        });
    });

    // Confirm modal
    document.getElementById("confirm-cancel").addEventListener("click", closeConfirm);
    document.getElementById("confirm-ok").addEventListener("click", () => {
        const cb = adminState.confirmCallback;
        closeConfirm();
        if (cb) cb();
    });
    document.getElementById("confirm-modal").addEventListener("click", (e) => {
        if (e.target.id === "confirm-modal") closeConfirm();
    });

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeConfirm();
    });
}

// ============================================================
// LOAD STATS
// ============================================================
async function loadStats() {
    try {
        const res = await fetch("/api/admin/stats", { credentials: "include" });
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("stat-total-users").textContent = data.total_users || 0;
        document.getElementById("stat-banned").textContent = data.banned_users || 0;
        document.getElementById("stat-admins").textContent = data.admin_users || 0;
        document.getElementById("stat-guests").textContent = data.guest_users || 0;
        document.getElementById("stat-encodes").textContent = data.total_encodes || 0;
        document.getElementById("stat-decodes").textContent = data.total_decodes || 0;
    } catch (e) {
        console.error("Lỗi load stats:", e);
    }
}

// ============================================================
// LOAD USERS
// ============================================================
async function loadUsers() {
    const tbody = document.getElementById("users-tbody");
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Đang tải...</td></tr>';

    try {
        const res = await fetch("/api/admin/users", { credentials: "include" });
        if (!res.ok) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-row">❌ Không có quyền admin</td></tr>';
            return;
        }
        adminState.users = await res.json();
        renderUsers(adminState.users);
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">❌ Lỗi kết nối</td></tr>';
    }
}

function filterUsers(query) {
    if (!query) {
        renderUsers(adminState.users);
        return;
    }
    const filtered = adminState.users.filter(u =>
        u.username.toLowerCase().includes(query)
    );
    renderUsers(filtered);
}

function renderUsers(users) {
    const tbody = document.getElementById("users-tbody");
    tbody.innerHTML = "";

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Chưa có user nào</td></tr>';
        return;
    }

    for (const u of users) {
        const tr = document.createElement("tr");

        // ID
        const tdId = document.createElement("td");
        tdId.textContent = u.id;
        tdId.className = "td-id";
        tr.appendChild(tdId);

        // Username
        const tdUser = document.createElement("td");
        tdUser.textContent = u.username;
        tdUser.className = "td-username";
        tr.appendChild(tdUser);

        // Vai trò
        const tdRole = document.createElement("td");
        if (u.is_admin) {
            tdRole.innerHTML = '<span class="badge badge-admin">👑 Admin</span>';
        } else if (u.username.startsWith("guest_")) {
            tdRole.innerHTML = '<span class="badge badge-guest">👤 Guest</span>';
        } else {
            tdRole.innerHTML = '<span class="badge badge-user">👤 User</span>';
