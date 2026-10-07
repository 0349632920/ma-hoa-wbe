// ============================================================
// STATE
// ============================================================
let state = {
    mode: "encode",
    algo: "base64",
    algoLabel: "📦 Base64",
    algos: null,
};

// ============================================================
// KHỞI TẠO
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
    await loadAlgos();
    bindEvents();
});

async function loadAlgos() {
    try {
        const res = await fetch("/api/algos");
        const data = await res.json();
        state.algos = data;
        document.getElementById("algo-count").textContent = data.total;
    } catch (e) {
        console.error("Lỗi load algos:", e);
    }
}

// ============================================================
// BIND EVENTS
// ============================================================
function bindEvents() {
    // Toggle mode
    document.querySelectorAll(".toggle-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".toggle-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.mode = btn.dataset.mode;
            document.getElementById("btn-run-text").textContent =
                state.mode === "encode" ? "⚙ MÃ HÓA" : "🔓 GIẢI MÃ";
        });
    });

    // Mở modal chọn algo
    document.getElementById("algo-picker").addEventListener("click", openModal);
    document.getElementById("close-modal").addEventListener("click", closeModal);
    document.getElementById("algo-modal").addEventListener("click", (e) => {
        if (e.target.id === "algo-modal") closeModal();
    });

    // Search
    document.getElementById("search").addEventListener("input", (e) => {
        renderAlgoList(e.target.value.toLowerCase());
    });

    // Toggle hiện/ẩn khóa
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

    // Nút MÃ HÓA / GIẢI MÃ
    document.getElementById("btn-run").addEventListener("click", runProcess);

    // Đảo chiều
    document.getElementById("btn-swap").addEventListener("click", () => {
        const inp = document.getElementById("input");
        const out = document.getElementById("output");
        inp.value = out.value;
        out.value = "";
        updateCount();
    });

    // Xóa
    document.getElementById("btn-clear").addEventListener("click", () => {
        document.getElementById("input").value = "";
        document.getElementById("output").value = "";
        updateCount();
    });

    // Copy kết quả
    document.getElementById("copy-out").addEventListener("click", () => {
        const out = document.getElementById("output");
        if (out.value) {
            navigator.clipboard.writeText(out.value);
            showToast("✅ Đã sao chép!");
        }
    });

    // Count ký tự
    document.getElementById("input").addEventListener("input", updateCount);

    // Phím tắt Ctrl+Enter để chạy
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
// MODAL
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
// XỬ LÝ
// ============================================================
async function runProcess() {
    const text = document.getElementById("input").value;
    const key = document.getElementById("key").value;
    const btn = document.getElementById("btn-run");

    if (!text) {
        showToast("⚠ Chưa nhập văn bản!", true);
        return;
    }

    // Loading
    btn.disabled = true;
    const originalText = document.getElementById("btn-run-text").textContent;
    document.getElementById("btn-run-text").innerHTML =
        `<span class="loading"></span> Đang xử lý...`;

    try {
        const res = await fetch("/api/process", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mode: state.mode,
                algo: state.algo,
                text: text,
                key: key,
            })
        });

        const data = await res.json();

        if (data.success) {
            document.getElementById("output").value = data.result;
            showToast(`✅ ${state.mode === "encode" ? "Mã hóa" : "Giải mã"} thành công!`);
        } else {
            showToast(`❌ ${data.error}`, true);
        }
    } catch (e) {
        showToast(`❌ Lỗi kết nối: ${e.message}`, true);
    } finally {
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