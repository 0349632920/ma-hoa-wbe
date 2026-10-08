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
    // Toggle mode với hiệu ứng slider
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
// CHUYỂN MODE VỚI HIỆU ỨNG SLIDER
// ============================================================
function switchMode(newMode) {
    const slider = document.getElementById("transition-slider");
    const sliderBg = document.getElementById("slider-bg");
    const sliderIcon = document.getElementById("slider-icon");
    const sliderText = document.getElementById("slider-text");
    const sliderSubtext = document.getElementById("slider-subtext");
    const main = document.querySelector(".main");

    // Cấu hình theo mode mới
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

    // Reset animation
    slider.classList.remove("active");
    void slider.offsetWidth;
    slider.classList.add("active");

    // Đổi UI khi slider đang che (400ms)
    setTimeout(() => {
        state.mode = newMode;

        // Đổi nút toggle active
        document.querySelectorAll(".toggle-btn").forEach(b => {
            b.classList.toggle("active", b.dataset.mode === newMode);
        });

        // Đổi text nút chính
        document.getElementById("btn-run-text").textContent =
            newMode === "encode" ? "⚙ MÃ HÓA" : "🔓 GIẢI MÃ";

        // Đổi class body → CSS tự đổi màu
        document.body.classList.toggle("decode-mode", newMode === "decode");

        // Đổi placeholder
        document.getElementById("input").placeholder =
            newMode === "encode"
                ? "Nhập văn bản cần mã hóa..."
                : "Dán nội dung cần giải mã vào đây...";

        // Đổi tiêu đề panel
        const titles = document.querySelectorAll(".panel-title");
        if (newMode === "encode") {
            titles[0].textContent = "Văn bản gốc";
            titles[1].textContent = "Kết quả";
        } else {
            titles[0].textContent = "Văn bản đã mã hóa";
            titles[1].textContent = "Kết quả giải mã";
        }

        // Hiệu ứng panel
        main.classList.add("switching");
        setTimeout(() => main.classList.remove("switching"), 800);

        // Đưa kết quả cũ lên input nếu input trống
        const inp = document.getElementById("input");
        const out = document.getElementById("output");
        if (out.value && !inp.value) {
            inp.value = out.value;
            out.value = "";
            updateCount();
        }
    }, 400);

    // Xóa class sau khi animation xong
    setTimeout(() => {
        slider.classList.remove("active");
    }, 800);
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
