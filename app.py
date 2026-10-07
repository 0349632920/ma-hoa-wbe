# -*- coding: utf-8 -*-
"""
Mã Hóa Chữ - Web App với hiệu ứng slider chuyển cảnh
"""
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ===== Import crypto utils =====
from crypto_utils import ENCODERS, GROUP_ORDER, get_grouped

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/algos", methods=["GET"])
def api_algos():
    return jsonify({
        "grouped": get_grouped(),
        "order": GROUP_ORDER,
        "total": len(ENCODERS)
    })

@app.route("/api/process", methods=["POST"])
def api_process():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Thiếu dữ liệu"}), 400

    mode = data.get("mode", "encode")
    algo = data.get("algo", "base64")
    text = data.get("text", "")
    key = data.get("key", "")

    if algo not in ENCODERS:
        return jsonify({"error": f"Không tìm thấy thuật toán: {algo}"}), 400

    if not text:
        return jsonify({"error": "Chưa nhập văn bản"}), 400

    label, group, enc_fn, dec_fn = ENCODERS[algo]
    fn = enc_fn if mode == "encode" else dec_fn

    try:
        result = fn(text, key)
        return jsonify({
            "success": True,
            "result": result,
            "algo_label": label,
            "mode": mode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "algos": len(ENCODERS)})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
