const { app, BrowserWindow, dialog, Menu, shell } = require("electron");
const net = require("node:net");
const http = require("node:http");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

// ────────────────────────────────────────────────────────────────
// 天鉴·索舆 桌面外壳
// 形态对齐探微：无边框深色窗口 + 内嵌引擎；区别只在于这里的引擎是本地 Python 服务端。
// 启动顺序：挑一个空闲端口 → 拉起 resources/bin/suoyu-server.exe → 探活 → 加载页面。
// ────────────────────────────────────────────────────────────────

let win = null;
let server = null;
let serverPort = 0;
let quitting = false;

const LOG_DIR = () => {
  const dir = path.join(app.getPath("userData"), "logs");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
};

function log(line) {
  try {
    fs.appendFileSync(
      path.join(LOG_DIR(), "shell.log"),
      `[${new Date().toISOString()}] ${line}\n`,
    );
  } catch {
    /* 日志写不进去也不影响主流程 */
  }
}

/** 端口占用探测：优先 5113，被占了就往后找 */
function portFree(port) {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once("error", () => resolve(false));
    tester.once("listening", () => tester.close(() => resolve(true)));
    tester.listen(port, "127.0.0.1");
  });
}

async function pickPort() {
  for (let port = 5113; port < 5163; port += 1) {
    if (await portFree(port)) return port;
  }
  return 0;
}

function serverExe() {
  const name = process.platform === "win32" ? "suoyu-server.exe" : "suoyu-server";
  // 打包后引擎放在 resources/bin；开发时直接用源码仓库里的 dist 产物
  const candidates = [
    path.join(process.resourcesPath || "", "bin", name),
    path.join(__dirname, "..", "dist", name),
  ];
  return candidates.find((p) => p && fs.existsSync(p)) || "";
}

function startServer(port) {
  const exe = serverExe();
  if (!exe) {
    log("engine binary missing");
    return null;
  }
  const dataDir = path.join(app.getPath("userData"), "data");
  fs.mkdirSync(dataDir, { recursive: true });
  log(`start engine ${exe} port=${port} data=${dataDir}`);
  const child = spawn(exe, [], {
    cwd: path.dirname(exe),
    env: {
      ...process.env,
      ARLX_PORT: String(port),
      ARLX_HOST: "127.0.0.1",
      ARLX_DATA: dataDir,
      PYTHONIOENCODING: "utf-8",
      PYTHONUTF8: "1",
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const out = fs.createWriteStream(path.join(LOG_DIR(), "engine.log"), { flags: "a" });
  child.stdout?.pipe(out);
  child.stderr?.pipe(out);
  child.on("exit", (code) => log(`engine exited code=${code}`));
  return child;
}

// 端口上可能已有别的服务（例如本地跑着旧版开发后端），
// 只判 200 会把别人的系统当成就绪的引擎，必须认应用标识。
function probe(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/api/status", timeout: 1500 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        if (body.length < 4096) body += chunk;
      });
      res.on("end", () => {
        if (res.statusCode !== 200) return resolve(false);
        try {
          const data = JSON.parse(body);
          // 天鉴·索舆 的 /api/status 一定带 app 字段，别的服务不会
          resolve(typeof data?.app === "string" && data.app.includes("索舆"));
        } catch {
          resolve(false);
        }
      });
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitReady(port, timeoutMs = 60000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await probe(port)) return true;
    // 首启动要建库、装内置字典，慢一点是正常的
    await new Promise((r) => setTimeout(r, 600));
  }
  return false;
}

/**
 * 站内链接在应用自己的窗口里打开，不调用系统浏览器。
 * 任何一次外链拉起都会让桌面外壳失去「单窗口平台」的形态。
 */
function openInnerWindow(url) {
  const child = new BrowserWindow({
    width: 1320,
    height: 880,
    backgroundColor: "#060b11",
    title: "天鉴·索舆",
    titleBarStyle: "hidden",
    titleBarOverlay: { color: "#060b11", symbolColor: "#d9e7ef", height: 46 },
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  child.loadURL(url).catch(() => log(`inner window load failed ${url}`));
  return child;
}

function createWindow() {
  win = new BrowserWindow({
    width: 1500,
    height: 940,
    minWidth: 1180,
    minHeight: 720,
    show: false,
    backgroundColor: "#060b11",
    title: "天鉴·索舆",
    titleBarStyle: "hidden",
    titleBarOverlay: { color: "#060b11", symbolColor: "#d9e7ef", height: 46 },
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  const showWindow = (why) => {
    if (!win || win.isDestroyed() || win.isVisible()) return;
    log(`show window (${why})`);
    win.show();
  };
  win.once("ready-to-show", () => showWindow("ready-to-show"));
  setTimeout(() => showWindow("fallback"), 2500);
  // 站内点开链接一律留在应用内，避免启动/点击时弹出系统浏览器
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url) && url.includes("127.0.0.1")) {
      win && win.loadURL(url);
      return { action: "deny" };
    }
    if (/^https?:/i.test(url)) {
      openInnerWindow(url);
    }
    return { action: "deny" };
  });
  // 应用外壳只加载本地引擎；其它地址一律进内嵌窗口，不在主窗口里导航走
  win.webContents.on("will-navigate", (ev, url) => {
    if (!url.startsWith("http://127.0.0.1:")) {
      ev.preventDefault();
      if (/^https?:/i.test(url)) openInnerWindow(url);
    }
  });
  win.on("closed", () => {
    win = null;
  });
}

function stopServer() {
  if (!server) return;
  const pid = server.pid;
  // Windows 上只 kill 父进程会留下引擎子进程占着端口，下次启动又起一个；
  // 用 taskkill /T 连整棵树一起收，退出后不留孤儿。
  try {
    if (process.platform === "win32" && pid) {
      require("node:child_process").spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
        windowsHide: true,
      });
    } else {
      server.kill();
    }
  } catch {
    /* 已经退出了 */
  }
  server = null;
}

if (process.env.SUOYU_SAFE_MODE === "1") app.disableHardwareAcceleration();

process.on("uncaughtException", (err) => log(`uncaughtException ${err && err.stack}`));

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);
  serverPort = await pickPort();
  if (!serverPort) {
    dialog.showErrorBox("天鉴·索舆", "找不到可用端口（5113-5162 全被占用）。");
    app.quit();
    return;
  }
  server = startServer(serverPort);
  createWindow();
  if (!win) return;
  const ok = await waitReady(serverPort);
  if (!ok) {
    log("engine not ready in time");
    const choice = dialog.showMessageBoxSync(win, {
      type: "error",
      title: "引擎未能启动",
      message: "本地侦察引擎在 60 秒内没有就绪。",
      detail: `端口 ${serverPort}\n日志：${path.join(LOG_DIR(), "engine.log")}`,
      buttons: ["打开日志目录", "退出"],
      defaultId: 0,
    });
    if (choice === 0) shell.openPath(LOG_DIR());
    app.quit();
    return;
  }
  await win.loadURL(`http://127.0.0.1:${serverPort}/`);
});

app.on("before-quit", () => {
  quitting = true;
  stopServer();
});

app.on("window-all-closed", () => {
  stopServer();
  app.quit();
});

app.on("activate", () => {
  if (!win && !quitting) {
    serverPort = serverPort || 5113;
    createWindow();
    win && server && win.loadURL(`http://127.0.0.1:${serverPort}/`);
  }
});
