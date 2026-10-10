const $ = id => document.getElementById(id);

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

// ==================== TABS ====================
document.querySelectorAll('.admin-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.admin-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.querySelector(`.admin-panel[data-panel="${tab.dataset.tab}"]`).classList.add('active');
    });
});

// ==================== STATS ====================
async function loadStats() {
    try {
        const res = await fetch('/api/admin/stats');
        const s = await res.json();
        $('stats').innerHTML = `
            <div class="stat-card"><div class="num">${s.total_users || 0}</div><div class="lbl">👥 Người dùng</div></div>
            <div class="stat-card"><div class="num">${s.banned_users || 0}</div><div class="lbl">🚫 Bị khóa</div></div>
            <div class="stat-card"><div class="num">${s.total_history || 0}</div><div class="lbl">📜 Lịch sử</div></div>
            <div class="stat-card"><div class="num">${s.deleted_users || 0}</div><div class="lbl">🗑 Đã xóa</div></div>
        `;
    } catch (e) { /* ignore */ }
}

// ==================== USERS ====================
async function loadUsers() {
    try {
        const res = await fetch('/api/admin/users');
        const users = await res.json();
        $('users-body').innerHTML = users.map(u => `
            <tr>
                <td>${u.id}</td>
                <td>${escapeHtml(u.username)}</td>
                <td>${u.role === 'admin' ? '<span class="badge badge-admin">Admin</span>' : 'User'}</td>
                <td><span class="badge badge-${u.status}">${u.status}</span></td>
                <td>${u.warning_count}/3</td>
                <td>${u.last_login ? new Date(u.last_login).toLocaleString('vi-VN') : '—'}</td>
                <td>
                    <button class="btn btn-sm" onclick="openWarnModal(${u.id}, '${escapeHtml(u.username)}')">⚠️ Cảnh báo</button>
                    ${u.status === 'active'
                        ? `<button class="btn btn-sm" onclick="openBanModal(${u.id}, '${escapeHtml(u.username)}')">🚫 Khóa</button>`
                        : `<button class="btn btn-sm" onclick="unbanUser(${u.id})">✅ Mở</button>`}
                    <button class="btn btn-sm" onclick="delUser(${u.id})">🗑</button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="7" class="muted" style="text-align:center">Chưa có user</td></tr>';
    } catch (e) { /* ignore */ }
}

async function unbanUser(id) {
    if (!confirm('Mở khóa user này?')) return;
    await fetch(`/api/admin/unban/${id}`, {method: 'POST'});
    loadUsers(); loadStats(); loadBans();
}

async function delUser(id) {
    const reason = prompt('Lý do xóa:', 'Vi phạm');
    if (reason === null) return;
    await fetch(`/api/admin/user/${id}`, {
        method: 'DELETE',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({reason})
    });
    loadUsers(); loadStats();
}

// ==================== WARNINGS LIST ====================
async function loadWarnings() {
    try {
        const res = await fetch('/api/admin/warnings');
        const rows = await res.json();
        const icons = {notice: '📘', warning: '⚠️', danger: '🚨'};
        $('warnings-body').innerHTML = rows.map(w => `
            <tr>
                <td>${w.id}</td>
                <td>${escapeHtml(w.username || '—')}</td>
                <td>${escapeHtml(w.title)}</td>
                <td>${escapeHtml(w.reason).slice(0, 40)}</td>
                <td>${icons[w.severity] || '⚠️'} ${w.severity}</td>
                <td>${w.acknowledged ? '✅' : '⏳'}</td>
                <td>${escapeHtml(w.moderator)}</td>
                <td>${new Date(w.created_at).toLocaleString('vi-VN')}</td>
                <td><button class="btn btn-sm" onclick="delWarning(${w.id})">🗑</button></td>
            </tr>
        `).join('') || '<tr><td colspan="9" class="muted" style="text-align:center">Chưa có cảnh báo</td></tr>';
    } catch (e) { /* ignore */ }
}

async function delWarning(id) {
    if (!confirm('Xóa cảnh báo này?')) return;
    await fetch(`/api/admin/warnings/${id}`, {method: 'DELETE'});
    loadWarnings();
}

// ==================== BANS LIST ====================
async function loadBans() {
    try {
        const res = await fetch('/api/admin/bans');
        const rows = await res.json();
        $('bans-body').innerHTML = rows.map(b => `
            <tr>
                <td>${b.id}</td>
                <td>${escapeHtml(b.username || '—')}</td>
                <td>${escapeHtml(b.reason || '').slice(0, 40)}</td>
                <td>${escapeHtml(b.moderator || '')}</td>
                <td>${new Date(b.banned_at).toLocaleString('vi-VN')}</td>
                <td>${b.is_permanent ? '∞' : (b.expires_at ? new Date(b.expires_at).toLocaleString('vi-VN') : '—')}</td>
                <td>${b.is_permanent ? '🚫 Vĩnh viễn' : '⏱ Tạm thời'}</td>
                <td>${b.is_active
                    ? `<button class="btn btn-sm" onclick="unbanUser(${b.user_id})">✅ Mở</button>`
                    : '<span class="muted">Đã hết</span>'}</td>
            </tr>
        `).join('') || '<tr><td colspan="8" class="muted" style="text-align:center">Chưa có ban</td></tr>';
    } catch (e) { /* ignore */ }
}

// ==================== HISTORY ====================
async function loadHistory() {
    try {
        const res = await fetch('/api/admin/history');
        const rows = await res.json();
        $('history-body').innerHTML = rows.map(r => `
            <tr>
                <td>${escapeHtml(r.username || '—')}</td>
                <td>${r.algo_label}</td>
                <td>${r.operation === 'encode' ? '🔒' : '🔓'}</td>
                <td title="${escapeHtml(r.input_text)}">${escapeHtml(r.input_text).slice(0, 40)}</td>
                <td title="${escapeHtml(String(r.output_text))}">${escapeHtml(String(r.output_text)).slice(0, 40)}</td>
                <td>${new Date(r.created_at).toLocaleString('vi-VN')}</td>
            </tr>
        `).join('') || '<tr><td colspan="6" class="muted" style="text-align:center">Chưa có lịch sử</td></tr>';
    } catch (e) { /* ignore */ }
}

// ==================== WARN MODAL ====================
function openWarnModal(uid, username) {
    $('warn-user-id').value = uid;
    $('warn-username').textContent = username;
    $('warn-title').value = '';
    $('warn-reason').value = '';
    $('warn-severity').value = 'warning';
    $('warn-modal-overlay').style.display = 'flex';
}

document.addEventListener('click', (e) => {
    if (e.target.id === 'warn-modal-close' || e.target.id === 'warn-modal-cancel') {
        $('warn-modal-overlay').style.display = 'none';
    }
    if (e.target.id === 'warn-modal-overlay') {
        e.target.style.display = 'none';
    }
});

$('warn-modal-submit').onclick = async () => {
    const uid = parseInt($('warn-user-id').value);
    const title = $('warn-title').value.trim();
    const reason = $('warn-reason').value.trim();
    const severity = $('warn-severity').value;

    if (!title) { alert('Nhập tiêu đề!'); return; }
    if (!reason) { alert('Nhập lý do!'); return; }

    try {
        const res = await fetch(`/api/admin/warn/${uid}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({title, reason, severity})
        });
        const data = await res.json();
        if (data.ok) {
            $('warn-modal-overlay').style.display = 'none';
            alert(`✅ Đã gửi cảnh báo!\nSố lần vi phạm: ${data.warning_count}/3`
                + (data.auto_banned ? '\n🚫 Tài khoản đã bị khóa tự động!' : ''));
            loadUsers(); loadWarnings(); loadStats(); loadBans();
        } else {
            alert('❌ ' + (data.error || 'Lỗi'));
        }
    } catch (e) { alert('Lỗi kết nối'); }
};

// ==================== BAN MODAL ====================
function openBanModal(uid, username) {
    $('ban-user-id').value = uid;
    $('ban-username').textContent = username;
    $('ban-reason').value = '';
    $('ban-duration').value = '0';
    $('ban-modal-overlay').style.display = 'flex';
}

document.addEventListener('click', (e) => {
    if (e.target.id === 'ban-modal-close' || e.target.id === 'ban-modal-cancel') {
        $('ban-modal-overlay').style.display = 'none';
    }
    if (e.target.id === 'ban-modal-overlay') {
        e.target.style.display = 'none';
    }
});

$('ban-modal-submit').onclick = async () => {
    const uid = parseInt($('ban-user-id').value);
    const reason = $('ban-reason').value.trim() || 'Vi phạm quy định';
    const duration = parseInt($('ban-duration').value);

    try {
        const res = await fetch(`/api/admin/ban/${uid}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reason, duration_hours: duration})
        });
        const data = await res.json();
        if (data.ok) {
            $('ban-modal-overlay').style.display = 'none';
            alert(`✅ Đã khóa user ${uid}`);
            loadUsers(); loadBans(); loadStats();
        } else {
            alert('❌ ' + (data.error || 'Lỗi'));
        }
    } catch (e) { alert('Lỗi kết nối'); }
};

// ==================== INIT ====================
loadStats();
loadUsers();
loadWarnings();
loadBans();
loadHistory();
setInterval(() => { loadStats(); loadUsers(); }, 30000);
