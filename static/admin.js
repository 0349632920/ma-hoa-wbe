// ============================================================
// STATE
// ============================================================
let adminState = {
    users: [],
    history: [],
    currentTab: "users",
    confirmCallback: null,
    banTarget: null,
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

    // History mode filter
    document.getElementById("history-mode").addEventListener("change", () => {
        loadHistory();
    });

    // Refresh buttons
    document.getElementById("btn-refresh-users").addEventListener("click", loadUsers);
    document.getElementById("btn-refresh-history").addEventListener("click", loadHistory);
    document.getElementById("btn-clear-history").addEventListener("click", () => {
        showConfirm(
            "🗑 Xóa hết lịch sử?",
            "Toàn bộ lịch sử mã hóa của tất cả users sẽ bị xóa. Không thể hoàn tác!",
            async () => {
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
                        const data = await res.json();
                        showToast("❌ " + (data.error || "Lỗi xóa"), true);
                    }
                } catch (e) {
                    showToast("❌ Lỗi kết nối", true);
                }
            }
        );
    });

    // ===== CONFIRM MODAL =====
    document.getElementById("confirm-cancel").addEventListener("click", closeConfirm);
    document.getElementById("confirm-ok").addEventListener("click", () => {
        const cb = adminState.confirmCallback;
        closeConfirm();
        if (cb) cb();
    });
    document.getElementById("confirm-modal").addEventListener("click", (e) => {
        if (e.target.id === "confirm-modal") closeConfirm();
    });

    // ===== BAN MODAL =====
    document.querySelectorAll(".ban-duration-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".ban-duration-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            adminState.banDuration = btn.dataset.duration;
        });
    });
    document.getElementById("ban-cancel").addEventListener("click", closeBanModal);
    document.getElementById("ban-confirm").addEventListener("click", confirmBan);
    document.getElementById("ban-modal").addEventListener("click", (e) => {
        if (e.target.id === "ban-modal") closeBanModal();
    });

    // Esc
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeConfirm();
            closeBanModal();
        }
    });
}

// ============================================================
// LOAD STATS
// ============================================================
async function loadStats() {
    try {
        const res = await fetch("/api/admin/stats", { credentials: "include" });
        if (!res.ok) {
            console.error("Lỗi load stats:", res.status);
            return;
        }
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
        console.error("Lỗi load users:", e);
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
            let banText = "🚫 Đã cấm";
            if (u.banned_until) {
                banText = "⏱ Cấm đến " + u.banned_until;
            } else {
                banText = "🚫 Cấm vĩnh viễn";
            }
            tdStatus.innerHTML = `<span class="badge badge-banned">${banText}</span>`;
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

        if (!u.is_admin) {
            if (u.is_banned) {
                // Nút mở cấm
                const btnUnban = document.createElement("button");
                btnUnban.className = "admin-action-btn unban";
                btnUnban.textContent = "✅ Mở cấm";
                btnUnban.addEventListener("click", () => unbanUser(u.id, u.username));
                tdActions.appendChild(btnUnban);
            } else {
                // Nút cấm
                const btnBan = document.createElement("button");
                btnBan.className = "admin-action-btn ban";
                btnBan.textContent = "🚫 Cấm";
                btnBan.addEventListener("click", () => openBanModal(u.id, u.username));
                tdActions.appendChild(btnBan);
            }

            // Nút xóa
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
// BAN USER — Mở modal
// ============================================================
function openBanModal(userId, username) {
    adminState.banTarget = { userId, username };
    adminState.banDuration = "1d";

    document.getElementById("ban-username").textContent = username;
    document.getElementById("ban-reason").value = "";

    // Reset duration buttons
    document.querySelectorAll(".ban-duration-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.duration === "1d");
    });

    document.getElementById("ban-modal").classList.add("show");
}

function closeBanModal() {
    document.getElementById("ban-modal").classList.remove("show");
    adminState.banTarget = null;
}

async function confirmBan() {
    if (!adminState.banTarget) return;

    const { userId, username } = adminState.banTarget;
    const duration = adminState.banDuration || "1d";
    const reason = document.getElementById("ban-reason").value.trim();

    const confirmBtn = document.getElementById("ban-confirm");
    confirmBtn.disabled = true;
    confirmBtn.textContent = "⏳ Đang cấm...";

    try {
        const res = await fetch(`/api/admin/users/${userId}/ban`, {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ duration, reason })
        });

        const data = await res.json();

        if (res.ok && data.success) {
            showToast(`✅ Đã cấm user "${username}"`);
            closeBanModal();
            await loadUsers();
            await loadStats();
        } else {
            showToast(`❌ ${data.error || "Lỗi không xác định"}`, true);
        }
    } catch (e) {
        showToast("❌ Lỗi kết nối: " + e.message, true);
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = "🚫 Cấm";
    }
}

// ============================================================
// UNBAN USER
// ============================================================
async function unbanUser(userId, username) {
    showConfirm(
        `✅ Mở cấm user "${username}"?`,
        "User này sẽ có thể đăng nhập và sử dụng lại bình thường.",
        async () => {
            try {
                const res = await fetch(`/api/admin/users/${userId}/unban`, {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" }
                });

                const data = await res.json();

                if (res.ok && data.success) {
                    showToast(`✅ Đã mở cấm user "${username}"`);
                    await loadUsers();
                    await loadStats();
                } else {
                    showToast(`❌ ${data.error || "Lỗi không xác định"}`, true);
                }
            } catch (e) {
                showToast("❌ Lỗi kết nối: " + e.message, true);
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
                if (res.ok && data.success) {
                    showToast(`✅ Đã xóa user "${username}"`);
                    await loadUsers();
                    await loadStats();
                } else {
                    showToast(`❌ ${data.error || "Lỗi không xác định"}`, true);
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
