const canvas = document.getElementById('snake-canvas');
const ctx = canvas.getContext('2d');
const scoreEl = document.getElementById('score');
const bestEl = document.getElementById('best');
const startBtn = document.getElementById('start-btn');
const pauseBtn = document.getElementById('pause-btn');
const restartBtn = document.getElementById('restart-btn');

const GRID = 20;
const CELL = canvas.width / GRID;

let snake, food, dir, nextDir, score, running, paused, gameLoop;

function init() {
    snake = [{x: 10, y: 10}];
    dir = {x: 1, y: 0};
    nextDir = {x: 1, y: 0};
    score = 0;
    running = false;
    paused = false;
    scoreEl.textContent = 0;
    spawnFood();
    draw();
}

function spawnFood() {
    do {
        food = {
            x: Math.floor(Math.random() * GRID),
            y: Math.floor(Math.random() * GRID)
        };
    } while (snake.some(s => s.x === food.x && s.y === food.y));
}

function draw() {
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    for (let i = 0; i <= GRID; i++) {
        ctx.beginPath();
        ctx.moveTo(i * CELL, 0);
        ctx.lineTo(i * CELL, canvas.height);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(0, i * CELL);
        ctx.lineTo(canvas.width, i * CELL);
        ctx.stroke();
    }

    // Vẽ mồi
    ctx.fillStyle = '#ff4757';
    ctx.beginPath();
    ctx.arc(food.x * CELL + CELL/2, food.y * CELL + CELL/2, CELL/2 - 2, 0, Math.PI * 2);
    ctx.fill();

    // Vẽ rắn
    snake.forEach((seg, i) => {
        ctx.fillStyle = i === 0 ? '#2ed573' : '#7bed9f';
        ctx.fillRect(seg.x * CELL + 1, seg.y * CELL + 1, CELL - 2, CELL - 2);
    });
}

function step() {
    if (paused) return;
    dir = nextDir;
    const head = {x: snake[0].x + dir.x, y: snake[0].y + dir.y};

    // Va vào tường
    if (head.x < 0 || head.x >= GRID || head.y < 0 || head.y >= GRID) {
        return gameOver();
    }
    // Va vào chính mình
    if (snake.some(s => s.x === head.x && s.y === head.y)) {
        return gameOver();
    }

    snake.unshift(head);

    // Ăn mồi
    if (head.x === food.x && head.y === food.y) {
        score += 10;
        scoreEl.textContent = score;
        spawnFood();
    } else {
        snake.pop();
    }
    draw();
}

async function gameOver() {
    running = false;
    clearInterval(gameLoop);
    startBtn.disabled = false;
    pauseBtn.disabled = true;

    try {
        const res = await fetch('/api/game/snake/score', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({score: score})
        });
        const data = await res.json();
        if (data.success) {
            bestEl.textContent = data.best;
            if (data.is_new_record) {
                alert('🎉 Kỷ lục mới: ' + score + ' điểm! +' + data.points_earned + ' điểm hệ thống');
            } else {
                alert('💀 Game Over! Điểm: ' + score);
            }
        }
    } catch (e) {
        alert('💀 Game Over! Điểm: ' + score);
    }
}

function setDirection(nx, ny) {
    // Không cho quay đầu 180°
    if (dir.x === -nx && dir.y === -ny) return;
    nextDir = {x: nx, y: ny};
}

document.addEventListener('keydown', e => {
    const k = e.key.toLowerCase();
    if (k === 'arrowup' || k === 'w') setDirection(0, -1);
    else if (k === 'arrowdown' || k === 's') setDirection(0, 1);
    else if (k === 'arrowleft' || k === 'a') setDirection(-1, 0);
    else if (k === 'arrowright' || k === 'd') setDirection(1, 0);
    else if (k === ' ') { e.preventDefault(); togglePause(); }
    if (['arrowup', 'arrowdown', 'arrowleft', 'arrowright', ' '].includes(k)) {
        e.preventDefault();
    }
});

function togglePause() {
    if (!running) return;
    paused = !paused;
    pauseBtn.textContent = paused ? '▶️ Tiếp tục' : '⏸️ Tạm dừng';
}

startBtn.addEventListener('click', () => {
    if (running) return;
    running = true;
    paused = false;
    startBtn.disabled = true;
    pauseBtn.disabled = false;
    pauseBtn.textContent = '⏸️ Tạm dừng';
    gameLoop = setInterval(step, 120);
});

pauseBtn.addEventListener('click', togglePause);

restartBtn.addEventListener('click', () => {
    clearInterval(gameLoop);
    init();
    startBtn.disabled = false;
    pauseBtn.disabled = true;
    pauseBtn.textContent = '⏸️ Tạm dừng';
});

// Load kỷ lục ban đầu
fetch('/api/game/snake/best')
    .then(r => r.json())
    .then(d => {
        if (d.success) bestEl.textContent = d.best;
    })
    .catch(() => {});

init();
