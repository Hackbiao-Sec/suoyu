const { app, BrowserWindow, dialog, ipcMain, Menu, shell } = require("electron");
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
// 窗口按钮：主窗口不用 titleBarOverlay（原生按钮会压在顶栏菜单上且配色跟界面无关），
// 改由网页顶栏自绘，按钮通过 preload 桥接到这里的 ipcMain 处理。
// ────────────────────────────────────────────────────────────────

let win = null;
let server = null;
let serverPort = 0;
let quitting = false;
// 引擎子进程提前退出时记下来：探活还在傻等 60 秒，用户看到的就是「卡住 + 白屏」
let engineExited = null;

// 启动动画：跑满 5 秒再切主界面；淡出留给页面自己做，切过去时不留硬切
const SPLASH_MS = 5000;
const SPLASH_FADE_MS = 560;
let splashStartedAt = 0;
let splashReady = false;
let splashGone = false;
let pendingStep = "";

// ── 自绘窗口按钮的 IPC ─────────────────────────────────────────
// 按发送方定位窗口：内嵌窗口和外链窗口共用同一套网页按钮，不写死主窗口。
const senderWindow = (event) => BrowserWindow.fromWebContents(event.sender);

ipcMain.on("win:minimize", (event) => {
  const target = senderWindow(event);
  if (target) target.minimize();
});

ipcMain.on("win:toggle-maximize", (event) => {
  const target = senderWindow(event);
  if (!target) return;
  if (target.isMaximized()) target.unmaximize();
  else target.maximize();
});

ipcMain.on("win:close", (event) => {
  const target = senderWindow(event);
  if (target) target.close();
});

ipcMain.on("win:is-maximized", (event) => {
  const target = senderWindow(event);
  event.returnValue = Boolean(target && target.isMaximized());
});

/** 把最大化状态推给网页，按钮才能换「最大化 / 还原」图形 */
function trackMaximized(target) {
  const push = () => {
    if (target.isDestroyed()) return;
    target.webContents.send("win:maximized", target.isMaximized());
  };
  target.on("maximize", push);
  target.on("unmaximize", push);
}

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

/** 窗口 / 任务栏图标：安装包把它放在 resources 根，开发时读 assets。 */
function appIcon() {
  const packed = path.join(process.resourcesPath || "", "icon.ico");
  const local = path.join(__dirname, "assets", "icon.ico");
  if (packed && fs.existsSync(packed)) return packed;
  if (fs.existsSync(local)) return local;
  return undefined;
}

/** 安装版随包携带的工具目录（构建时把 tools/ 放到 resources/bin/tools）。 */
function bundledTools() {
  const dir = path.join(process.resourcesPath || "", "bin", "tools");
  try {
    return fs.existsSync(dir) ? dir : "";
  } catch {
    return "";
  }
}

/**
 * 工具装在哪：安装版直接用随包目录，装进去的工具能留到下次启动；
 * 便携版每次解压到新的临时目录，所以改用用户数据目录，否则退出就全没了。
 */
function toolsDir() {
  const bundled = bundledTools();
  if (bundled) return bundled;
  const dir = path.join(app.getPath("userData"), "tools");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function startServer(port) {
  const exe = serverExe();
  if (!exe) {
    log("engine binary missing");
    return null;
  }
  const dataDir = path.join(app.getPath("userData"), "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const toolRoot = toolsDir();
  log(`start engine ${exe} port=${port} data=${dataDir} tools=${toolRoot}`);
  engineExited = null;
  const child = spawn(exe, [], {
    cwd: path.dirname(exe),
    env: {
      ...process.env,
      ARLX_PORT: String(port),
      ARLX_HOST: "127.0.0.1",
      ARLX_DATA: dataDir,
      ARLX_TOOLS: toolRoot,
      // 随包工具也挂到 PATH：个别工具会自己再拉兄弟程序，光靠绝对路径找不到
      PATH: toolRoot + path.delimiter + (process.env.PATH || ""),
      PYTHONIOENCODING: "utf-8",
      PYTHONUTF8: "1",
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const out = fs.createWriteStream(path.join(LOG_DIR(), "engine.log"), { flags: "a" });
  child.stdout?.pipe(out);
  child.stderr?.pipe(out);
  child.on("error", (err) => {
    engineExited = { code: null, signal: null, at: Date.now(), error: String(err) };
    log(`engine spawn error ${err}`);
  });
  child.on("exit", (code, signal) => {
    engineExited = { code, signal, at: Date.now() };
    log(`engine exited code=${code} signal=${signal}`);
  });
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

/** 就绪后取一次版本号，日志里留下这次跑的是哪个前端构建 */
function readStatus(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/api/status", timeout: 2000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk;
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve(null);
        }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

/** 启动期间窗口里是本地 splash，等引擎时用这两句更新文案，避免白屏干等 */
function applySplash(kind, text) {
  if (!win || win.isDestroyed() || splashGone) return;
  win.webContents
    .executeJavaScript(`window.__suoyu${kind} && window.__suoyu${kind}(${JSON.stringify(text)})`)
    .catch(() => {});
}

function splashStep(text) {
  pendingStep = text;
  // splash 还没加载完就先攒着，did-finish-load 时补一条，文案不会丢
  if (!splashReady) return;
  applySplash("Step", text);
}

function splashFail(text) {
  applySplash("Fail", text);
  splashGone = true;
}

/**
 * 收尾：先让动画跑满 5 秒，再让页面淡出，最后才载入主界面。
 * 引擎比动画慢时（首次建库）就地等它，进度条停在 100% 并提示预热中。
 */
async function finishSplash() {
  if (splashGone) return;
  const left = SPLASH_MS - (Date.now() - splashStartedAt);
  if (left > 0) await new Promise((r) => setTimeout(r, left));
  if (win && !win.isDestroyed()) {
    await win.webContents
      .executeJavaScript("window.__suoyuFinish && window.__suoyuFinish()")
      .catch(() => {});
  }
  await new Promise((r) => setTimeout(r, SPLASH_FADE_MS));
  splashGone = true;
}

async function waitReady(port, timeoutMs = 120000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await probe(port)) return true;
    // 引擎已经挂了就别再等满一分钟：onefile 的引导进程退出就是真退出
    if (engineExited) return false;
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
  // 外链窗口里是别人的页面，没有我们的顶栏可以放自绘按钮，
  // 所以保留系统标题栏，保证这类窗口始终能拖动和关闭。
  const child = new BrowserWindow({
    width: 1320,
    height: 880,
    backgroundColor: "#060b11",
    title: "天鉴·索舆",
    autoHideMenuBar: true,
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
    // 只留无框窗口：不设 titleBarOverlay，右上角不会再有原生按钮压在功能区上
    titleBarStyle: "hidden",
    icon: appIcon(),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, "preload.js"),
      spellcheck: false,
    },
  });
  trackMaximized(win);

  // 先挂本地 splash：引擎冷启动十几秒，这段窗口期不能是白的
  splashReady = false;
  splashGone = false;
  splashStartedAt = Date.now();
  win.webContents.on("did-finish-load", () => {
    if (splashGone) return;
    splashReady = true;
    if (pendingStep) applySplash("Step", pendingStep);
  });
  win.loadFile(path.join(__dirname, "splash.html"), {
    query: { v: app.getVersion() },
  }).catch((err) => log(`splash load failed ${err}`));

  const showWindow = (why) => {
    if (!win || win.isDestroyed() || win.isVisible()) return;
    log(`show window (${why})`);
    win.show();
  };
  win.once("ready-to-show", () => showWindow("ready-to-show"));
  setTimeout(() => showWindow("fallback"), 1200);
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

/** 出错弹窗里带一段引擎日志尾巴，用户不用自己去翻文件 */
function engineLogTail(lines = 12) {
  try {
    const text = fs.readFileSync(path.join(LOG_DIR(), "engine.log"), "utf8");
    return text.trimEnd().split(/\r?\n/).slice(-lines).join("\n");
  } catch {
    return "";
  }
}

if (process.env.SUOYU_SAFE_MODE === "1") app.disableHardwareAcceleration();

process.on("uncaughtException", (err) => log(`uncaughtException ${err && err.stack}`));

// 连着双击图标时，第二个实例不该再拉一个引擎去抢端口，把已有窗口提到前台即可
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();

app.on("second-instance", () => {
  if (!win || win.isDestroyed()) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
});

app.whenReady().then(async () => {
  if (!gotLock) return;
  Menu.setApplicationMenu(null);
  serverPort = await pickPort();
  if (!serverPort) {
    dialog.showErrorBox("天鉴·索舆", "找不到可用端口（5113-5162 全被占用）。");
    app.quit();
    return;
  }
  createWindow();
  if (!win) return;
  splashStep("正在拉起本地引擎…");
  server = startServer(serverPort);
  const ok = await waitReady(serverPort);
  if (!ok) {
    const exited = engineExited;
    log(`engine not ready exited=${JSON.stringify(exited)}`);
    splashFail(exited ? "引擎启动失败" : "引擎启动超时");
    const headline = exited
      ? `本地侦察引擎启动后立即退出${exited.error ? `：${exited.error}` : `（code=${exited.code}）`}。`
      : "本地侦察引擎在 120 秒内没有就绪。";
    const tail = engineLogTail();
    const choice = dialog.showMessageBoxSync(win, {
      type: "error",
      title: "引擎未能启动",
      message: headline,
      detail: `端口 ${serverPort}\n日志：${path.join(LOG_DIR(), "engine.log")}${tail ? `\n\n最后几行：\n${tail}` : ""}`,
      buttons: ["打开日志目录", "退出"],
      defaultId: 0,
    });
    if (choice === 0) shell.openPath(LOG_DIR());
    app.quit();
    return;
  }
  const status = await readStatus(serverPort);
  log(`engine ready port=${serverPort} version=${status?.version} build=${status?.build}`);
  splashStep(
    status?.version ? `引擎 v${status.version} 就绪，正在进入作战台…` : "引擎就绪，正在进入作战台…",
  );
  // 动画至少跑满 5 秒，再淡出，最后才把窗口切到工具本体
  await finishSplash();
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
