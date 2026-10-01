'use strict';

/**
 * Electron main process — Agentic Blockchain Forensics desktop shell.
 * UI talks only to the Node backend at localhost:3000.
 */

const { app, BrowserWindow, dialog, ipcMain, shell, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');

let mainWindow = null;

function loadAppConfig() {
  try {
    const configPath = path.join(__dirname, '../backend-node/config/app.config.json');
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch {
    return { branding: { windowTitle: 'Agentic Blockchain Forensics' } };
  }
}

/** Classic application menu (File / Edit / View / Window / Help). */
function buildAppMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac
      ? [
          {
            label: app.name,
            submenu: [
              { role: 'about' },
              { type: 'separator' },
              { role: 'services' },
              { type: 'separator' },
              { role: 'hide' },
              { role: 'hideOthers' },
              { role: 'unhide' },
              { type: 'separator' },
              { role: 'quit' },
            ],
          },
        ]
      : []),
    {
      label: 'File',
      submenu: [isMac ? { role: 'close' } : { role: 'quit' }],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        ...(isMac
          ? [
              { role: 'pasteAndMatchStyle' },
              { role: 'delete' },
              { role: 'selectAll' },
            ]
          : [
              { role: 'delete' },
              { type: 'separator' },
              { role: 'selectAll' },
            ]),
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        ...(isMac
          ? [
              { type: 'separator' },
              { role: 'front' },
              { type: 'separator' },
              { role: 'window' },
            ]
          : [{ role: 'close' }]),
      ],
    },
    {
      role: 'help',
      submenu: [
        {
          label: 'Agentic Blockchain Forensics Documentation',
          click: async () => {
            await shell.openExternal(
              'https://github.com/Syed-Abdul-Rehman-Nasir/agentic-blockchain-forensics'
            );
          },
        },
      ],
    },
  ];
  return Menu.buildFromTemplate(template);
}

function createWindow() {
  const appConfig = loadAppConfig();
  // Use a normal OS frame so maximize/restore/resize work on Windows and WSL/Linux.
  // The branded identity lives in the in-app #titlebar — not a frameless caption.
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    resizable: true,
    maximizable: true,
    minimizable: true,
    fullscreenable: true,
    frame: true,
    autoHideMenuBar: false,
    title: appConfig.branding?.windowTitle || 'Agentic Blockchain Forensics',
    backgroundColor: '#F7FAFD',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    // Always open windowed (not maximized) so restore/resize bounds are well-defined.
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    if (mainWindow.isFullScreen()) mainWindow.setFullScreen(false);
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(buildAppMenu());
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

/** Native file picker for forensic disk images (E01 + raw/split). */
ipcMain.handle('dialog:openFile', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select forensic disk image',
    properties: ['openFile'],
    filters: [
      {
        name: 'Forensic Images',
        extensions: ['E01', 'e01', '001', 'dd', 'img', 'raw', 'Ex01', 'L01'],
      },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

ipcMain.handle('shell:openExternal', async (_event, url) => {
  await shell.openExternal(url);
  return true;
});

/** Save HTML report to a temp file and open in the default browser. */
ipcMain.handle('report:openHtml', async (_event, html, caseId) => {
  const safe = String(caseId || 'report').replace(/[^\w.-]+/g, '_');
  const out = path.join(os.tmpdir(), `forensic_report_${safe}.html`);
  fs.writeFileSync(out, html, 'utf8');
  await shell.openPath(out);
  return out;
});

/** Save HTML report via Save dialog. */
ipcMain.handle('report:saveHtml', async (_event, html, caseId) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save forensic report',
    defaultPath: `report_${caseId || 'case'}.html`,
    filters: [{ name: 'HTML', extensions: ['html'] }],
  });
  if (result.canceled || !result.filePath) return null;
  fs.writeFileSync(result.filePath, html, 'utf8');
  return result.filePath;
});
