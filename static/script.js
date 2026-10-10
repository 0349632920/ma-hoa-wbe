// ==================== ELEMENTS ====================
const $ = id => document.getElementById(id);
const algoSelect = $('algo-select');
const keyInput = $('key-input');
const inputText = $('input-text');
const outputText = $('output-text');
const elapsed = $('elapsed');
const historyList = $('history-list');

// ==================== PROCESS ====================
async function process(op) {
    const text = inputText.value;
    if (!text) { outputText.value = '⚠️ Nhập văn bản trước'; return; }
    outputText.value = '⏳ Đang xử lý...';
    try {
        const res = await fetch('/api/process', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                algo: algoSelect.value,
                text,
                key: keyInput.value,
                operation: op
            })
        });
        const data = await res.json();
        if (data.ok) {
            outputText.value = data.result;
            elapsed.textContent = data.elapsed_ms;
            loadHistory();
        } else {
            if (data.banned) {
                location.href = '/banned?reason=' + encodeURIComponent(data.reason || '');
                return;
            }
            outputText.value = '❌ ' + data.error;
        }
    } catch (e) {
        outputText.value = '❌ Lỗi kết nối: ' + e.message;
    }
}

$('btn-encode').onclick = () => process('encode');
$('btn-decode').onclick = () => process('decode');
$('btn-clear').onclick = () => {
    inputText.value = ''; outputText.value = ''; elapsed.textContent = '0';
};
$('btn-swap').onclick = () => {
    const t = inputText.value;
    inputText.value = outputText.value;
    outputText.value = t;
};
$('btn-copy').onclick = async () => {
    if (!outputText.value) return;
    try {
        await navigator.clipboard.writeText(outputText.value);
        const btn = $('btn-copy');
        const old = btn.textContent;
        btn.textContent = '✅ Đã copy';
        setTimeout(() => btn.textContent = old, 1500);
    } catch (e) { alert('Không thể copy'); }
};

// ==================== HISTORY ====================
async function loadHistory() {
    try {
        const res = await fetch('/api/history');
        if (!res.ok) return;
        const rows = await res.json();
        if (!rows.length) {
            historyList.innerHTML = '<p class="muted">Chưa có lịch sử</p>';
            return;
        }
        historyList.innerHTML = rows.map(r => `
            <div class="history-item">
                <div class="meta">
                    <span>${r.algo_label} • ${r.operation === 'encode' ? '🔒' : '🔓'}</span>
                    <span>
                        ${new Date(r.created_at).toLocaleString('vi-VN')}
                        <span class="del" onclick="delHistory(${r.id})">✖</span>
                    </span>
                </div>
                <div class="text">→ ${escapeHtml(r.input_text).slice(0, 80)}</div>
                <div class="text" style="color:#10b981">← ${escapeHtml(String(r.output_text)).slice(0, 80)}</div>
            </div>
        `).join('');
    } catch (e) { /* ignore */ }
}

async function delHistory(id) {
    if (!confirm('Xóa mục này?')) return;
    await fetch('/api/history/' + id, {method: 'DELETE'});
    loadHistory();
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

$('btn-refresh-history').onclick = loadHistory;

// ==================== WARNING SYSTEM (kiểu Roblox) ====================
let warningQueue = [];
let currentWarning = null;

// Âm thanh cảnh báo bằng Web Audio API
function playWarningSound(severity) {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const now = ctx.currentTime;
        const freqs = severity === 'danger'
            ? [880, 660, 440] : severity === 'warning'
            ? [660, 550, 440] : [550, 440];
        freqs.forEach((f, i) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain); gain.connect(ctx.destination);
            osc.frequency.value = f;
            osc.type = 'square';
            gain.gain.setValueAtTime(0, now + i * 0.15);
            gain.gain.linearRampToValueAtTime(0.15, now + i * 0.15 + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.15 + 0.15);
            osc.start(now + i * 0.15);
            osc.stop(now + i * 0.15 + 0.15);
        });
    } catch (e) { /* ignore */ }
}

async function checkPendingWarnings() {
    try {
        const res = await fetch('/api/warnings/pending');
        if (!res.ok) return;
        const data = await res.json();
        const warnings = data.warnings || [];
        const total = data.warning_count || 0;

        updateWarningBadge(total);

        if (warnings.length > 0) {
            warningQueue = warnings;
            if (!currentWarning) showNextWarning();
        }
    } catch (e) { /* ignore */ }
}

function updateWarningBadge(count) {
    const badge = $('warning-badge');
    if (!badge) return;
    if (count > 0) {
        badge.style.display = 'inline-block';
        badge.textContent = count;
    } else {
        badge.style.display = 'none';
    }
}

function showNextWarning() {
    if (warningQueue.length === 0) {
        currentWarning = null;
        return;
    }
    currentWarning = warningQueue.shift();
    const w = currentWarning;

    const overlay = $('warning-overlay');
    const modal = $('warning-modal');

    $('warning-from').textContent = w.moderator || 'Moderator';
    $('warning-title-text').textContent = w.title;
    $('warning-reason').textContent = w.reason;

    const icons = { notice: '📘', warning: '⚠️', danger: '🚨' };
    const titles = {
        notice: 'NHẮC NHỞ',
        warning: 'BẠN ĐÃ BỊ CẢNH BÁO',
        danger: 'CẢNH BÁO NGHIÊM TRỌNG'
    };
    $('warning-icon').textContent = icons[w.severity] || '⚠️';
    $('warning-title').textContent = titles[w.severity] || 'CẢNH BÁO';

    // Đếm số lần vi phạm - lấy từ API đã fetch
    fetch('/api/warnings/pending').then(r => r.json()).then(data => {
        const count = data.warning_count || 1;
        const display = Math.min(count, 3);
        $('warning-count').textContent = `${display}/3`;
        const pct = Math.min(count / 3 * 100, 100);
        $('warning-count-fill').style.width = pct + '%';
        $('warning-count-note').textContent = count >= 3
            ? '🚫 Bạn đã vi phạm 3 lần - Tài khoản sẽ bị khóa!'
            : `⚠️ Còn ${3 - count} lần nữa sẽ bị khóa tài khoản vĩnh viễn!`;
    }).catch(() => {
        $('warning-count').textContent = '1/3';
        $('warning-count-fill').style.width = '33%';
    });

    if (w.severity === 'danger') {
        modal.classList.add('shake');
        setTimeout(() => modal.classList.remove('shake'), 500);
    }

    playWarningSound(w.severity);

    overlay.style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

// Xác nhận đã đọc
document.addEventListener('click', async (e) => {
    if (e.target.id === 'warning-acknowledge' && currentWarning) {
        const wid = currentWarning.id;
        try {
            await fetch(`/api/warnings/${wid}/acknowledge`, { method: 'POST' });
        } catch (err) { /* ignore */ }

        $('warning-overlay').style.display = 'none';
        document.body.style.overflow = '';

        currentWarning = null;

        if (warningQueue.length > 0) {
            setTimeout(showNextWarning, 300);
        } else {
            checkPendingWarnings();
        }
    }
});

// Lịch sử cảnh báo
document.addEventListener('click', async (e) => {
    if (e.target.id === 'warning-history-btn' || e.target.closest('#warning-history-btn')) {
        await loadWarningHistory();
    }
    if (e.target.id === 'warning-history-close') {
        $('warning-history-overlay').style.display = 'none';
    }
    if (e.target.id === 'warning-history-overlay') {
        e.target.style.display = 'none';
    }
});

async function loadWarningHistory() {
    try {
        const res = await fetch('/api/warnings/me');
        const warnings = await res.json();
        const list = $('warning-history-list');

        if (!warnings.length) {
            list.innerHTML = '<p class="muted" style="padding:20px;text-align:center">Chưa có cảnh báo</p>';
        } else {
            list.innerHTML = warnings.map(w => `
                <div class="warning-item severity-${w.severity}">
                    <div class="warning-item-title">
                        <span>${escapeHtml(w.title)}</span>
                        <span class="warning-item-status ${w.acknowledged ? 'read' : 'unread'}">
                            ${w.acknowledged ? '✓ Đã đọc' : '● Chưa đọc'}
                        </span>
                    </div>
                    <div class="warning-item-reason">${escapeHtml(w.reason)}</div>
                    <div class="warning-item-meta">
                        <span>👤 ${escapeHtml(w.moderator)}</span>
                        <span>${new Date(w.created_at).toLocaleString('vi-VN')}</span>
                    </div>
                </div>
            `).join('');
        }
        $('warning-history-overlay').style.display = 'flex';
    } catch (e) { /* ignore */ }
}

// ==================== INIT ====================
loadHistory();
checkPendingWarnings();
setInterval(checkPendingWarnings, 15000);

// Kiểm tra ban mỗi 30s
setInterval(async () => {
    try {
        const res = await fetch('/api/ban/status');
        const data = await res.json();
        if (data.banned) {
            location.href = '/banned?reason=' + encodeURIComponent(data.reason || '') +
                            '&exp=' + encodeURIComponent(data.expires_at || '0') +
                            '&u=' + encodeURIComponent(document.body.dataset.user || '');
        }
    } catch (e) { /* ignore */ }
}, 30000);
