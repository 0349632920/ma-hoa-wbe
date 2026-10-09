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
        }
        tr.appendChild(tdRole);

        // Trạng thái
        const tdStatus = document.createElement("td");
        if (u.is_banned) {
            tdStatus.innerHTML = '<span class="badge badge-banned">🚫 Đã cấm</span>';
        } else {
            tdStatus.innerHTML = '<span class="badge badge-active">✅ Hoạt động</span>';
        }
        tr.appendChild(tdStatus);

        // Số lần dùng
        const tdCount = document.createElement("td");
        tdCount.textContent = u.op_count || 0;
        tr.appendChild(tdCount);

        // Ngày tạo
        const tdDate = document.createElement("td");
        tdDate.textContent = u.created_at || "-";
        tdDate.className = "td-date";
        tr.appendChild(tdDate);

        // Actions
        const tdActions = document.createElement("td");
        tdActions.className = "td-actions";

        // Nút ban/unban
        if (!u.is_admin) {
            const btnBan = document.createElement("button");
            btnBan.className = "admin-action-btn " + (u.is_banned ? "unban" : "ban");
            btnBan.textContent = u.is_banned ? "✅ Mở cấm" : "🚫 Cấm";
            btnBan.addEventListener("click", () => toggleBan(u.id, u.username, !u.is_banned));
            tdActions.appendChild(btnBan);
        }

        // Nút xóa
        if (!u.is_admin) {
            const btnDel = document.createElement("button");
            btnDel.className = "admin-action-btn delete";
            btnDel.textContent = "🗑 Xóa";
            btnDel.addEventListener("click", () => deleteUser(u.id, u.username));
            tdActions.appendChild(btnDel);
        }

        // Nút xem lịch sử
        const btnHistory = document.createElement("button");
        btnHistory.className = "admin-action-btn history";
        btnHistory.textContent = "📜 Lịch sử";
        btnHistory.addEventListener("click", () => viewUserHistory(u.username));
        tdActions.appendChild(btnHistory);

        tr.appendChild(tdActions);
        tbody.appendChild(tr);
    }
}

// ============================================================
// BAN / UNBAN
// ============================================================
function toggleBan(userId, username, ban) {
    const action = ban ? "cấm" : "mở cấm";
    const icon = ban ? "🚫" : "✅";
    showConfirm(
        `${icon} ${ban ? "Cấm" : "Mở cấm"} user "${username}"?`,
        ban ? "User này sẽ không thể đăng nhập hoặc mã hóa/giải mã." : "User này sẽ có thể dùng lại bình thường.",
        async () => {
            try {
                const res = await fetch(`/api/admin/users/${userId}/ban`, {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ban })
                });
                const data = await res.json();
                if (res.ok) {
                    showToast(`✅ Đã ${action} user "${username}"`);
                    loadUsers();
                    loadStats();
                } else {
                    showToast(`❌ ${data.error}`, true);
                }
            } catch (e) {
                showToast("❌ Lỗi kết nối", true);
            }
        }
    );
}

// ============================================================
// DELETE USER
// ============================================================
function deleteUser(userId, username) {
    showConfirm(
        `🗑 Xóa user "${username}"?`,
        "Toàn bộ lịch sử của user này cũng sẽ bị xóa. Không thể hoàn tác!",
        async () => {
            try {
                const res = await fetch(`/api/admin/users/${userId}`, {
                    method: "DELETE",
                    credentials: "include"
                });
                const data = await res.json();
                if (res.ok) {
                    showToast(`✅ Đã xóa user "${username}"`);
                    loadUsers();
                    loadStats();
                } else {
                    showToast(`❌ ${data.error}`, true);
                }
            } catch (e) {
                showToast("❌ Lỗi kết nối", true);
            }
        }
    );
}

// ============================================================
// VIEW USER HISTORY
// ============================================================
function viewUserHistory(username) {
    // Chuyển sang tab history + set filter
    document.getElementById("history-search").value = username;
    document.querySelectorAll(".admin-tab").forEach(t => {
        t.classList.toggle("active", t.dataset.tab === "history");
    });
    document.getElementById("tab-users").classList.add("hidden");
    document.getElementById("tab-history").classList.remove("hidden");
    adminState.currentTab = "history";
    loadHistory();
}

// ============================================================
// LOAD HISTORY
// ============================================================
async function loadHistory() {
    const tbody = document.getElementById("history-tbody");
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Đang tải...</td></tr>';

    const username = document.getElementById("history-search").value.trim();
    const mode = document.getElementById("history-mode").value;

    const params = new URLSearchParams();
    if (username) params.append("username", username);
    if (mode) params.append("mode", mode);
    params.append("limit", "200");

    try {
        const res = await fetch(`/api/admin/history?${params}`, { credentials: "include" });
        if (!res.ok) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-row">❌ Không có quyền admin</td></tr>';
            return;
        }
        const data = await res.json();
        renderHistory(data);
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">❌ Lỗi kết nối</td></tr>';
    }
}

function renderHistory(items) {
    const tbody = document.getElementById("history-tbody");
    tbody.innerHTML = "";

    if (!items || items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-row">Chưa có lịch sử</td></tr>';
        return;
    }

    for (const h of items) {
        const tr = document.createElement("tr");

        tr.appendChild(mkCell(h.id, "td-id"));
        tr.appendChild(mkCell(h.username, "td-username"));

        const tdMode = document.createElement("td");
        if (h.mode === "encode") {
            tdMode.innerHTML = '<span class="badge badge-encode">🔒 Mã hóa</span>';
        } else {
            tdMode.innerHTML = '<span class="badge badge-decode">🔓 Giải mã</span>';
        }
        tr.appendChild(tdMode);

        tr.appendChild(mkCell(h.algo, "td-algo"));
        tr.appendChild(mkCell(truncate(h.input_text, 60), "td-input"));
        tr.appendChild(mkCell(truncate(h.output_text, 60), "td-output"));
        tr.appendChild(mkCell(h.created_at, "td-date"));

        tbody.appendChild(tr);
    }
}

function mkCell(text, className) {
    const td = document.createElement("td");
    td.textContent = text || "";
    if (className) td.className = className;
    return td;
}

function truncate(text, max) {
    if (!text) return "";
    return text.length > max ? text.substring(0, max) + "..." : text;
}

// ============================================================
// CONFIRM MODAL
// ============================================================
function showConfirm(title, text, callback) {
    document.getElementById("confirm-title").textContent = title;
    document.getElementById("confirm-text").textContent = text;
    adminState.confirmCallback = callback;
    document.getElementById("confirm-modal").classList.add("show");
}

function closeConfirm() {
    document.getElementById("confirm-modal").classList.remove("show");
    adminState.confirmCallback = null;
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
