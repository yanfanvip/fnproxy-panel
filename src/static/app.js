// fnproxy Panel Frontend JavaScript

const API_BASE = '/api';
let currentToken = localStorage.getItem('token');
let currentUser = JSON.parse(localStorage.getItem('user') || '{}');
let ws = null;
let terminalPingTimer = null;
let terminalHeartbeatTimer = null;
let terminalInstance = null;
let terminalFitAddon = null;
let terminalResizeBound = false;
let terminalFocusBound = false;
let terminalSessions = [];
let sshConnectionsCache = [];
let usersCache = [];
let activeTerminalSessionId = null;
let currentModalVariant = 'default';
let modalHeightFrame = null;
let authPublicKeyCache = null;
let modalBusy = false;

// 初始化
function init() {
    bindEvents();
    bindResponsiveLayout();
    loadActiveTerminalSessions(false);
    showPage('dashboard');
}

// 绑定事件
function bindEvents() {
    // 导航
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            showPage(page);
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            if (isMobileLayout()) {
                closeSidebar();
            }
        });
    });

    // 设置表单
    document.getElementById('settingsForm').addEventListener('submit', handleSaveSettings);
    document.addEventListener('fullscreenchange', handleTerminalFullscreenChange);
}

function bindResponsiveLayout() {
    window.addEventListener('resize', () => {
        if (!isMobileLayout()) {
            closeSidebar();
        }
        updateModalHeight();
    });
}

function isMobileLayout() {
    return window.innerWidth <= 900;
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    const isOpen = sidebar.classList.contains('open');
    sidebar.classList.toggle('open', !isOpen);
    backdrop.classList.toggle('active', !isOpen);
    document.body.classList.toggle('sidebar-open', !isOpen);
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    if (!sidebar || !backdrop) return;
    sidebar.classList.remove('open');
    backdrop.classList.remove('active');
    document.body.classList.remove('sidebar-open');
}

async function fetchAuthPublicKey(force = false) {
    if (!force && authPublicKeyCache) {
        return authPublicKeyCache;
    }
    const data = await apiRequest('/auth/public-key');
    if (!data.success || !data.data?.public_key) {
        throw new Error(data.error || '读取加密公钥失败');
    }
    authPublicKeyCache = data.data.public_key;
    return authPublicKeyCache;
}

function pemToArrayBuffer(pem) {
    const cleaned = String(pem || '').replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// Forge 库加载状态
let forgeLibPromise = null;

// Chart.js 库加载状态
let chartLibPromise = null;
let networkChartInstance = null;

// 动态加载 Chart.js 库
function loadChartLib() {
    if (chartLibPromise) {
        return chartLibPromise;
    }
    chartLibPromise = new Promise((resolve, reject) => {
        if (window.Chart) {
            resolve(window.Chart);
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js';
        script.onload = () => {
            if (window.Chart) {
                resolve(window.Chart);
            } else {
                reject(new Error('Chart.js 加载失败'));
            }
        };
        script.onerror = () => reject(new Error('加载 Chart.js 失败'));
        document.head.appendChild(script);
    });
    return chartLibPromise;
}

// 动态加载 forge 库
function loadForgeLib() {
    if (forgeLibPromise) {
        return forgeLibPromise;
    }
    forgeLibPromise = new Promise((resolve, reject) => {
        if (window.forge) {
            resolve(window.forge);
            return;
        }
        const script = document.createElement('script');
        script.src = '/static/vendor/forge.min.js';
        script.onload = () => {
            if (window.forge) {
                resolve(window.forge);
            } else {
                reject(new Error('Forge 库加载失败'));
            }
        };
        script.onerror = () => reject(new Error('加载加密库失败，请检查网络连接'));
        document.head.appendChild(script);
    });
    return forgeLibPromise;
}

// 使用 forge 库进行 RSA-OAEP 加密
async function encryptWithForge(value, publicKeyPem) {
    const forge = await loadForgeLib();
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(value, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() }
    });
    // 转换为 Base64URL
    const base64 = forge.util.encode64(encrypted);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

// 检测 Web Crypto API 是否可用
function isWebCryptoAvailable() {
    return !!(window.crypto && window.crypto.subtle);
}

async function encryptSecureValue(value) {
    if (!value) {
        return '';
    }
    const publicKeyPem = await fetchAuthPublicKey();
    
    // 优先使用 Web Crypto API
    if (isWebCryptoAvailable()) {
        try {
            const publicKey = await window.crypto.subtle.importKey(
                'spki',
                pemToArrayBuffer(publicKeyPem),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
            const encrypted = await window.crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                new TextEncoder().encode(value)
            );
            return `enc::${arrayBufferToBase64Url(encrypted)}`;
        } catch (e) {
            console.warn('Web Crypto API 加密失败，尝试使用 forge 库:', e.message);
        }
    }
    
    // 回退到 forge 库
    const encryptedBase64Url = await encryptWithForge(value, publicKeyPem);
    return `enc::${encryptedBase64Url}`;
}

function generateRandomHexToken(length = 32) {
    const normalizedLength = Number.isFinite(Number(length)) ? Number(length) : 32;
    const byteLength = Math.max(1, Math.ceil(normalizedLength / 2));
    if (!window.crypto || !window.crypto.getRandomValues) {
        throw new Error('当前环境不支持安全随机数生成');
    }
    const bytes = new Uint8Array(byteLength);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('').slice(0, normalizedLength);
}

async function copyTextToClipboard(text) {
    const value = String(text || '');
    if (!value) {
        throw new Error('没有可复制的内容');
    }
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        return;
    }
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (!copied) {
        throw new Error('复制失败，请手动复制');
    }
}

async function copyUserToken(id) {
    const user = usersCache.find(item => item.id === id);
    if (!user || !String(user.token || '').trim()) {
        showToast('该用户尚未设置 token', 'error');
        return;
    }
    try {
        await copyTextToClipboard(user.token.trim());
        showToast(`已复制 ${user.username} 的 token`, 'success');
    } catch (err) {
        showToast(err.message || '复制 token 失败', 'error');
    }
}

// 当前选中的端口ID
let currentListenerId = null;
let currentListenerPort = null;
let currentListenerProtocol = null;
let listenerServicesRequestToken = 0;
let currentDefaultServiceId = null;
let currentDefaultServiceMode = 'simple';
let defaultServiceDraft = null;
let currentServiceMode = 'simple';
let currentServiceDraft = null;
let currentListenerServices = [];
let draggedServiceId = null;
let draggedServiceDropAfter = false;
let pendingConfirmResolve = null;
let currentListenerLogTarget = null;
let currentServiceLogTarget = null;
let currentLogDrawerContext = null;
let certificateOptionsCache = [];
let currentCertificateEditId = null;

// 显示页面
function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
    document.getElementById(page + 'Page').classList.remove('hidden');
    document.getElementById('pageTitle').textContent = getPageTitle(page);

    // 加载页面数据
    switch(page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'listeners':
            loadListeners();
            break;
        case 'certificates':
            loadCertificates();
            break;
        case 'listenerServices':
            // 服务配置页面单独处理
            break;
        case 'terminal':
            loadSSHConnections();
            loadActiveTerminalSessions(false);
            break;
        case 'users':
            loadUsers();
            break;
        case 'settings':
            loadSettings();
            break;
        case 'securityLogs':
            loadSecurityLogs();
            break;
    }
}

function getPageTitle(page) {
    const titles = {
        dashboard: '首页',
        listeners: '端口监听',
        certificates: '证书管理',
        terminal: '终端管理',
        users: '用户管理',
        securityLogs: '安全日志',
        settings: '设置'
    };
    return titles[page] || page;
}

function createServiceConfigDefaults(type, baseConfig = {}) {
    const hasOAuth = Object.prototype.hasOwnProperty.call(baseConfig, 'oauth');
    const hasAccessLog = Object.prototype.hasOwnProperty.call(baseConfig, 'access_log');
    const shared = {
        oauth: hasOAuth ? !!baseConfig.oauth : true,
        access_log: hasAccessLog ? !!baseConfig.access_log : false
    };

    switch (type) {
        case 'reverse_proxy':
            return {
                upstream: baseConfig.upstream || '',
                timeout: Number.isFinite(Number(baseConfig.timeout)) ? Number(baseConfig.timeout) : 30,
                ...shared
            };
        case 'static':
            return {
                root: baseConfig.root || '',
                browse: !!baseConfig.browse,
                index: baseConfig.index || 'index.html',
                ...shared
            };
        case 'redirect':
            return {
                to: baseConfig.to || '',
                ...shared
            };
        case 'url_jump':
            return {
                target_url: baseConfig.target_url || '',
                ...shared
            };
        case 'text_output':
            return {
                body: baseConfig.body || '',
                content_type: baseConfig.content_type || 'text/plain; charset=utf-8',
                status_code: Number.isFinite(Number(baseConfig.status_code)) ? Number(baseConfig.status_code) : 200,
                ...shared
            };
        default:
            return { ...shared };
    }
}

function getAdvancedConfigText(type, config = {}) {
    const advancedConfig = { ...config };
    ['upstream', 'timeout', 'root', 'browse', 'index', 'to', 'target_url', 'body', 'content_type', 'status_code', 'oauth', 'access_log'].forEach(key => {
        delete advancedConfig[key];
    });
    return Object.keys(advancedConfig).length ? JSON.stringify(advancedConfig, null, 2) : '';
}

function createDefaultServiceDraft(service = null) {
    const type = service?.type || '';
    const config = service?.config || {};
    return {
        type,
        config: createServiceConfigDefaults(type, config),
        advancedText: getAdvancedConfigText(type, config)
    };
}

function createServiceDraft(service = null) {
    const type = service?.type || 'reverse_proxy';
    const config = service?.config || {};
    return {
        id: service?.id || null,
        port_id: service?.port_id || currentListenerId,
        name: service?.name || '',
        type,
        domain: service?.domain || '',
        sort_order: Number(service?.sort_order || 0),
        certificate_id: '',
        enabled: service?.enabled !== false,
        config: createServiceConfigDefaults(type, config),
        advancedText: getAdvancedConfigText(type, config)
    };
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) {
        return;
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3200);
}

function showConfirmModal(message, options = {}) {
    const modal = document.getElementById('confirmModal');
    const title = document.getElementById('confirmTitle');
    const text = document.getElementById('confirmMessage');
    const confirmButton = document.getElementById('confirmModalConfirm');

    title.textContent = options.title || '确认操作';
    text.textContent = message;
    confirmButton.textContent = options.confirmText || '确认';
    confirmButton.className = `btn ${options.danger === false ? 'btn-primary' : 'btn-danger'}`;

    modal.classList.add('active');

    return new Promise(resolve => {
        pendingConfirmResolve = resolve;
        confirmButton.onclick = () => closeConfirmModal(true);
    });
}

function closeConfirmModal(result = false) {
    const modal = document.getElementById('confirmModal');
    modal.classList.remove('active');
    if (pendingConfirmResolve) {
        pendingConfirmResolve(result);
        pendingConfirmResolve = null;
    }
}

function formatRate(bytesPerSecond) {
    return `${formatBytes(bytesPerSecond || 0)}/s`;
}

function metricNumber(value, fallback = 0) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
}

function metricBytes(value) {
    return formatBytes(metricNumber(value, 0));
}

function escapeHtml(value = '') {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function hintIcon(text = '') {
    if (!text) return '';
    return `<span class="field-hint" tabindex="0" data-hint="${escapeHtml(text)}">i</span>`;
}

function labelWithHint(label, hint = '') {
    return `<label class="field-label">${label}${hintIcon(hint)}</label>`;
}

function checkboxLabelWithHint(label, hint = '', inputId = '', checked = false, extraAttributes = '') {
    return `
        <label class="checkbox-label">
            <input type="checkbox" id="${inputId}" ${checked ? 'checked' : ''} ${extraAttributes}>
            <span>${label}</span>
            ${hintIcon(hint)}
        </label>
    `;
}

function setModalVariant(variant = 'default') {
    const modalContent = document.querySelector('#modal .modal-content');
    if (!modalContent) return;
    currentModalVariant = variant;
    modalContent.classList.remove('modal-wide', 'modal-medium');
    if (variant === 'wide' || variant === 'service') {
        modalContent.classList.add('modal-wide');
    } else if (variant === 'medium' || variant === 'certificate' || variant === 'ssh' || variant === 'listener' || variant === 'user') {
        modalContent.classList.add('modal-medium');
    }
}

function setModalBusy(busy) {
    modalBusy = !!busy;
    const modal = document.getElementById('modal');
    const closeButton = modal?.querySelector('.modal-header .close-btn');
    const footerButtons = modal?.querySelectorAll('.modal-footer .btn') || [];
    if (closeButton) {
        closeButton.disabled = modalBusy;
        closeButton.style.pointerEvents = modalBusy ? 'none' : '';
        closeButton.style.opacity = modalBusy ? '0.5' : '';
    }
    footerButtons.forEach(button => {
        button.disabled = modalBusy;
    });
}

function showSSHTestModal(connectionName = '') {
    setModalVariant('medium');
    setModalBusy(true);
    document.getElementById('modalTitle').textContent = '测试 SSH 连接';
    document.getElementById('modalBody').innerHTML = `
        <div class="form-group">
            <label>连接名称</label>
            <div>${escapeHtml(connectionName || 'SSH 连接')}</div>
        </div>
        <div class="form-group">
            <label>当前状态</label>
            <div id="sshTestStatusText">正在测试连接，请稍候...</div>
        </div>
    `;
    const confirmButton = document.getElementById('modalConfirm');
    if (confirmButton) {
        confirmButton.textContent = '测试中...';
        confirmButton.onclick = null;
    }
    document.getElementById('modal').classList.add('active');
    scheduleModalHeightUpdate();
}

function finishSSHTestModal(message, success) {
    const statusText = document.getElementById('sshTestStatusText');
    if (statusText) {
        statusText.textContent = message || (success ? 'SSH 连接测试成功' : 'SSH 连接测试失败');
        statusText.style.color = success ? '#16a34a' : '#dc2626';
        statusText.style.fontWeight = '600';
    }
    const confirmButton = document.getElementById('modalConfirm');
    if (confirmButton) {
        confirmButton.textContent = '关闭';
        confirmButton.onclick = closeModal;
    }
    setModalBusy(false);
    scheduleModalHeightUpdate();
}

function getModalHeightLimit() {
    const viewportHeight = window.visualViewport?.height || window.innerHeight || document.documentElement.clientHeight || 0;
    return Math.floor(viewportHeight * 0.8);
}

function scheduleModalHeightUpdate() {
    if (modalHeightFrame) {
        cancelAnimationFrame(modalHeightFrame);
    }
    modalHeightFrame = requestAnimationFrame(() => {
        modalHeightFrame = null;
        updateModalHeight();
    });
}

function resetModalHeight() {
    const modal = document.getElementById('modal');
    const modalContent = modal?.querySelector('.modal-content');
    const modalBody = modal?.querySelector('.modal-body');
    if (modalHeightFrame) {
        cancelAnimationFrame(modalHeightFrame);
        modalHeightFrame = null;
    }
    if (modalContent) {
        modalContent.style.height = '';
        modalContent.style.maxHeight = '';
    }
    if (modalBody) {
        modalBody.style.maxHeight = '';
        modalBody.style.overflowY = '';
    }
}

function updateModalHeight() {
    const modal = document.getElementById('modal');
    if (!modal?.classList.contains('active')) {
        resetModalHeight();
        return;
    }

    const modalContent = modal.querySelector('.modal-content');
    const modalHeader = modal.querySelector('.modal-header');
    const modalBody = modal.querySelector('.modal-body');
    const modalFooter = modal.querySelector('.modal-footer');
    if (!modalContent || !modalHeader || !modalBody || !modalFooter) {
        return;
    }

    if (isMobileLayout()) {
        resetModalHeight();
        return;
    }

    const maxHeight = getModalHeightLimit();
    modalContent.style.height = 'auto';
    modalContent.style.maxHeight = `${maxHeight}px`;
    modalBody.style.maxHeight = 'none';
    modalBody.style.overflowY = 'visible';

    const naturalHeight = Math.ceil(modalHeader.offsetHeight + modalBody.scrollHeight + modalFooter.offsetHeight + 8);
    const targetHeight = Math.min(naturalHeight, maxHeight);
    const bodyHeight = Math.max(0, Math.floor(targetHeight - modalHeader.offsetHeight - modalFooter.offsetHeight));

    modalContent.style.height = `${targetHeight}px`;
    modalBody.style.maxHeight = `${bodyHeight}px`;
    modalBody.style.overflowY = naturalHeight > maxHeight ? 'auto' : 'visible';
}

async function drawNetworkChart(points = []) {
    const canvas = document.getElementById('networkChart');
    if (!canvas) return;

    try {
        await loadChartLib();
    } catch (e) {
        // 回退到简单文字提示
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#f8fafc';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#94a3b8';
        ctx.font = '14px sans-serif';
        ctx.fillText('图表组件加载失败', 20, canvas.height / 2);
        return;
    }

    // 销毁旧实例
    if (networkChartInstance) {
        networkChartInstance.destroy();
        networkChartInstance = null;
    }

    const labels = points.map(p => {
        const date = new Date(p.timestamp);
        return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
    });
    const inValues = points.map(p => Number(p.in_rate || 0));
    const outValues = points.map(p => Number(p.out_rate || 0));

    if (!points.length) {
        labels.push('');
        inValues.push(0);
        outValues.push(0);
    }

    networkChartInstance = new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: '入站',
                    data: inValues,
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#4f46e5'
                },
                {
                    label: '出站',
                    data: outValues,
                    borderColor: '#0ea5e9',
                    backgroundColor: 'rgba(14, 165, 233, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#0ea5e9'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 41, 59, 0.9)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    padding: 12,
                    cornerRadius: 8,
                    displayColors: true,
                    callbacks: {
                        label: function(context) {
                            return context.dataset.label + ': ' + formatRate(context.raw);
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(148, 163, 184, 0.15)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#64748b',
                        font: { size: 11 },
                        maxTicksLimit: 8,
                        maxRotation: 0
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(148, 163, 184, 0.15)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#64748b',
                        font: { size: 11 },
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

function renderLogs(containerId, logs, emptyText) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!logs || logs.length === 0) {
        container.innerHTML = `<div class="logs-empty">${emptyText}</div>`;
        return;
    }

    container.innerHTML = `
        <table class="logs-table">
            <thead>
                <tr>
                    <th style="width: 150px;">时间</th>
                    <th style="width: 70px;">状态</th>
                    <th class="logs-col-mobile-hidden" style="width: 80px;">方法</th>
                    <th>路径</th>
                    <th class="logs-col-mobile-hidden" style="width: 90px;">耗时</th>
                    <th class="logs-col-mobile-hidden" style="width: 100px;">流量</th>
                    <th class="logs-col-mobile-hidden" style="width: 150px;">来源</th>
                </tr>
            </thead>
            <tbody>
                ${logs.map(log => {
                    const statusClass = log.status_code >= 500 ? 'error' : log.status_code >= 400 ? 'warn' : 'ok';
                    return `
                        <tr>
                            <td>${new Date(log.timestamp).toLocaleString()}</td>
                            <td><span class="logs-status ${statusClass}">${log.status_code}</span></td>
                            <td class="logs-col-mobile-hidden">${escapeHtml(log.method)}</td>
                            <td class="path" title="${escapeHtml(`${log.path} ${log.host || ''}`)}">${escapeHtml(log.path)} <small>${escapeHtml(log.host || '')}</small></td>
                            <td class="logs-col-mobile-hidden">${log.duration_ms} ms</td>
                            <td class="logs-col-mobile-hidden">${formatBytes(log.bytes_out || 0)}</td>
                            <td class="logs-col-mobile-hidden">${escapeHtml(log.username || log.remote_addr || '-')}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

function openLogDrawer(title, subtitle = '') {
    document.getElementById('logDrawerTitle').textContent = title;
    document.getElementById('logDrawerSubtitle').textContent = subtitle;
    document.getElementById('logDrawer').classList.add('active');
    document.getElementById('logDrawerBackdrop').classList.add('active');
}

function closeLogDrawer() {
    document.getElementById('logDrawer').classList.remove('active');
    document.getElementById('logDrawerBackdrop').classList.remove('active');
}

function refreshLogDrawer() {
    if (!currentLogDrawerContext) {
        renderLogs('logDrawerBody', [], '点击日志按钮查看内容。');
        return;
    }

    if (currentLogDrawerContext.type === 'listener') {
        loadListenerLogs(currentLogDrawerContext.listenerId, currentLogDrawerContext.port);
        return;
    }

    if (currentLogDrawerContext.type === 'service') {
        loadServiceLogs(currentLogDrawerContext.serviceId, currentLogDrawerContext.serviceName);
    }
}

// API请求封装
async function apiRequest(url, options = {}) {
    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
    const headers = {
        ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
        ...options.headers
    };
    if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
    }

    const res = await fetch(`${API_BASE}${url}`, {
        ...options,
        headers
    });
    return res.json();
}

// 加载首页数据
async function loadDashboard() {
    try {
        const [statusData, listenersData, networkHistoryData] = await Promise.all([
            apiRequest('/status'),
            apiRequest('/listeners'),
            apiRequest('/metrics/network-history')
        ]);

        if (statusData.success) {
            const s = statusData.data;
            document.getElementById('uptime').textContent = s.uptime || '-';
            document.getElementById('memory').textContent = formatBytes(s.memory_used) || '-';
            document.getElementById('cpu').textContent = (s.cpu_usage ? s.cpu_usage.toFixed(1) : '-') + '%';
            document.getElementById('networkIn').textContent = formatRate(s.network_in_rate || 0);
            document.getElementById('networkOut').textContent = formatRate(s.network_out_rate || 0);
        }

        if (listenersData.success) {
            const active = listenersData.data.filter(l => l.enabled).length;
            document.getElementById('activePorts').textContent = active;
        }

        if (networkHistoryData.success) {
            drawNetworkChart(networkHistoryData.data || []);
        }
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

// 加载端口监听
async function loadListeners() {
    try {
        const [listenersData, metricsData] = await Promise.all([
            apiRequest('/listeners'),
            apiRequest('/metrics/listeners')
        ]);

        if (listenersData.success) {
            const container = document.getElementById('listenersCards');
            const metricMap = new Map((metricsData.success ? metricsData.data : []).map(item => [item.listener_id, item]));
            
            // 如果没有端口，显示空状态
            if (listenersData.data.length === 0) {
                container.innerHTML = '<div class="empty-state">暂无端口监听，点击右上角“添加监听”开始创建。</div>';
                return;
            }

            // 先显示端口列表（不等待服务数量）
            container.innerHTML = listenersData.data.map(l => {
                const stats = metricMap.get(l.id) || {};
                const activeConnections = metricNumber(stats.active_connections, 0);
                const requestCount = metricNumber(stats.request_count, 0);
                const bytesInTotal = metricNumber(stats.bytes_in_total, 0);
                const bytesOutTotal = metricNumber(stats.bytes_out_total, 0);
                const bytesInRate = metricNumber(stats.bytes_in_rate, 0);
                const bytesOutRate = metricNumber(stats.bytes_out_rate, 0);
                const running = !!l.running;
                const enabledStatusText = l.enabled ? '已启用' : '已关闭';
                const toggleTitle = running ? '停止监听' : '启动监听';
                const toggleButtonClass = running ? 'btn-warning' : 'btn-success';
                const toggleIcon = running ? '⏸' : '▶';
                return `
                <div class="listener-card" onclick="showListenerServices('${l.id}', ${l.port}, '${l.protocol}')">
                    ${l.protocol === 'https' ? `
                        <div class="listener-card-https-badge"></div>
                        <div class="listener-card-https-icon">🔒</div>
                    ` : ''}
                    <div class="listener-card-running-badge ${running ? 'running' : 'stopped'}"></div>
                    <div class="listener-card-running-icon">${running ? '▶' : '■'}</div>
                    <div class="listener-card-main">
                        <div class="listener-card-left">
                            <div class="listener-card-port-row">
                                <div class="listener-card-port">端口：${l.port}</div>
                                <span class="listener-enabled-badge ${l.enabled ? 'enabled' : 'disabled'}">${enabledStatusText}</span>
                            </div>
                            <div class="listener-card-stats">
                                <div class="listener-card-stat">
                                    <div class="listener-card-stat-value" id="service-count-${l.id}">-</div>
                                    <div class="listener-card-stat-label">服务数</div>
                                </div>
                                <div class="listener-card-stat listener-stat-mobile-hidden">
                                    <div class="listener-card-stat-value">${activeConnections}</div>
                                    <div class="listener-card-stat-label">活动连接</div>
                                </div>
                                <div class="listener-card-stat listener-stat-mobile-hidden">
                                    <div class="listener-card-stat-value">${requestCount}</div>
                                    <div class="listener-card-stat-label">请求数</div>
                                </div>
                                <div class="listener-card-stat">
                                    <div class="listener-card-stat-value">${metricBytes(bytesInTotal)}</div>
                                    <div class="listener-card-stat-label">入站流量</div>
                                </div>
                                <div class="listener-card-stat">
                                    <div class="listener-card-stat-value">${metricBytes(bytesOutTotal)}</div>
                                    <div class="listener-card-stat-label">出站流量</div>
                                </div>
                                <div class="listener-card-stat listener-stat-mobile-hidden">
                                    <div class="listener-card-stat-value">${formatRate(bytesInRate)}</div>
                                    <div class="listener-card-stat-label">入站流量/s</div>
                                </div>
                                <div class="listener-card-stat listener-stat-mobile-hidden">
                                    <div class="listener-card-stat-value">${formatRate(bytesOutRate)}</div>
                                    <div class="listener-card-stat-label">出站流量/s</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="listener-card-actions" onclick="event.stopPropagation()">
                        <button class="btn ${toggleButtonClass} icon-btn" title="${toggleTitle}" onclick="toggleListener('${l.id}')">
                            ${toggleIcon}
                        </button>
                        <button class="btn icon-btn" title="查看日志" onclick="loadListenerLogs('${l.id}', ${l.port})">📄</button>
                        <button class="btn btn-primary icon-btn" title="编辑监听" onclick="editListener('${l.id}')">✏️</button>
                        <button class="btn btn-danger icon-btn" title="删除监听" onclick="deleteListener('${l.id}')">🗑</button>
                    </div>
                </div>
                `;
            }).join('');

            // 异步加载每个端口的服务数量
            listenersData.data.forEach(async l => {
                try {
                    const servicesData = await apiRequest(`/services?port_id=${l.id}`);
                    const count = servicesData.success ? servicesData.data.length : 0;
                    const countEl = document.getElementById(`service-count-${l.id}`);
                    if (countEl) countEl.textContent = count;
                } catch (e) {
                    console.error('Failed to load service count for port', l.port, e);
                }
            });
        }
    } catch (err) {
        console.error('Failed to load listeners:', err);
    }
}

// 显示端口服务配置页面
async function showListenerServices(listenerId, port, protocol = null) {
    currentListenerId = listenerId;
    currentListenerPort = port;
    currentListenerProtocol = protocol;
    currentServiceLogTarget = null;
    document.getElementById('listenerServicesTitle').textContent = `[${port}]`;
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
    document.getElementById('listenerServicesPage').classList.remove('hidden');
    document.getElementById('pageTitle').textContent = '服务配置';
    await loadListenerServices(listenerId);
}

function isDefaultServiceRule(service) {
    const domain = String(service?.domain || '*').trim();
    return domain === '' || domain === '*';
}

function sortServicesForDisplay(services = []) {
    return [...services].sort((left, right) => {
        const leftDefault = isDefaultServiceRule(left);
        const rightDefault = isDefaultServiceRule(right);
        if (leftDefault !== rightDefault) {
            return leftDefault ? 1 : -1;
        }
        const leftOrder = Number(left?.sort_order || 0);
        const rightOrder = Number(right?.sort_order || 0);
        if (leftOrder !== rightOrder) {
            if (!leftOrder) return 1;
            if (!rightOrder) return -1;
            return leftOrder - rightOrder;
        }
        return String(left?.id || '').localeCompare(String(right?.id || ''));
    });
}

function moveServiceInOrder(services = [], draggedId, targetId, insertAfter = false) {
    const regular = services.filter(service => !isDefaultServiceRule(service));
    const defaults = services.filter(service => isDefaultServiceRule(service));
    const fromIndex = regular.findIndex(service => service.id === draggedId);
    const targetIndex = regular.findIndex(service => service.id === targetId);
    if (fromIndex === -1 || targetIndex === -1) {
        return services;
    }
    const [dragged] = regular.splice(fromIndex, 1);
    let nextIndex = targetIndex;
    if (fromIndex < targetIndex) {
        nextIndex -= 1;
    }
    if (insertAfter) {
        nextIndex += 1;
    }
    regular.splice(Math.max(0, nextIndex), 0, dragged);
    return [...regular, ...defaults];
}

function clearServiceDragState() {
    draggedServiceId = null;
    draggedServiceDropAfter = false;
    document.querySelectorAll('#servicesTableBody tr').forEach(row => {
        row.classList.remove('dragging', 'drag-over-top', 'drag-over-bottom');
    });
}

async function persistServiceOrder(services = []) {
    const orderedIds = services.filter(service => !isDefaultServiceRule(service)).map(service => service.id);
    const data = await apiRequest('/services/reorder', {
        method: 'POST',
        body: JSON.stringify({
            port_id: currentListenerId,
            ordered_ids: orderedIds
        })
    });
    if (!data.success) {
        throw new Error(data.error || '服务排序保存失败');
    }
}

function bindServiceSortHandlers() {
    const rows = document.querySelectorAll('#servicesTableBody tr[data-service-id]');
    rows.forEach(row => {
        const isLocked = row.dataset.defaultService === 'true';
        if (isLocked) {
            row.removeAttribute('draggable');
            return;
        }
        row.setAttribute('draggable', 'true');
        row.addEventListener('dragstart', () => {
            draggedServiceId = row.dataset.serviceId || null;
            row.classList.add('dragging');
        });
        row.addEventListener('dragend', () => {
            clearServiceDragState();
        });
        row.addEventListener('dragover', event => {
            event.preventDefault();
            const rect = row.getBoundingClientRect();
            const halfway = rect.top + rect.height / 2;
            draggedServiceDropAfter = event.clientY >= halfway;
            row.classList.toggle('drag-over-top', !draggedServiceDropAfter);
            row.classList.toggle('drag-over-bottom', draggedServiceDropAfter);
        });
        row.addEventListener('dragleave', () => {
            row.classList.remove('drag-over-top', 'drag-over-bottom');
        });
        row.addEventListener('drop', async event => {
            event.preventDefault();
            const targetId = row.dataset.serviceId || '';
            row.classList.remove('drag-over-top', 'drag-over-bottom');
            if (!draggedServiceId || !targetId || draggedServiceId === targetId) {
                clearServiceDragState();
                return;
            }
            const reordered = moveServiceInOrder(currentListenerServices, draggedServiceId, targetId, draggedServiceDropAfter);
            clearServiceDragState();
            try {
                await persistServiceOrder(reordered);
                currentListenerServices = reordered;
                await loadListenerServices();
                showToast('服务顺序已更新', 'success');
            } catch (err) {
                showToast(err.message || '服务顺序更新失败', 'error');
            }
        });
    });
}

// 加载端口下的服务
async function loadListenerServices(expectedListenerId = currentListenerId) {
    if (!expectedListenerId) return;

    const requestToken = ++listenerServicesRequestToken;
    const tbody = document.getElementById('servicesTableBody');
    const mobileList = document.getElementById('listenerServicesMobileList');
    tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: #7f8c8d; padding: 32px;">正在加载服务配置...</td></tr>';
    if (mobileList) {
        mobileList.innerHTML = '<div class="listener-service-card-empty">正在加载服务配置...</div>';
    }

    try {
        const [data, statsData] = await Promise.all([
            apiRequest(`/services?port_id=${expectedListenerId}`),
            apiRequest(`/metrics/services?port_id=${expectedListenerId}`)
        ]);
        if (requestToken !== listenerServicesRequestToken || expectedListenerId !== currentListenerId) {
            return;
        }

        if (data.success) {
            const services = sortServicesForDisplay((data.data || []).filter(service => service.port_id === expectedListenerId));
            const statsMap = new Map((statsData.success ? statsData.data : []).map(item => [item.service_id, item]));
            currentListenerServices = services;

            if (services.length === 0) {
                tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: #7f8c8d; padding: 40px;">当前端口暂无服务配置，点击“添加服务”创建。</td></tr>';
                if (mobileList) {
                    mobileList.innerHTML = '<div class="listener-service-card-empty">当前端口暂无服务配置，点击“添加服务”创建。</div>';
                }
                return;
            }

            const typeNames = {
                'reverse_proxy': '反向代理',
                'static': '静态文件',
                'redirect': '重定向',
                'url_jump': 'URL跳转',
                'text_output': '文本输出'
            };

            tbody.innerHTML = services.map(s => {
                const target = getServiceTarget(s);
                const stats = statsMap.get(s.id) || {};
                const enabled = s.enabled !== false;
                const isDefaultRule = isDefaultServiceRule(s);
                return `
                <tr class="${enabled ? '' : 'service-disabled-row'} ${isDefaultRule ? 'service-default-row' : 'service-sortable-row'}" data-service-id="${s.id}" data-default-service="${isDefaultRule ? 'true' : 'false'}">
                    <td class="service-sort-cell">
                        <button class="service-drag-handle ${isDefaultRule ? 'locked' : ''}" type="button" title="${isDefaultRule ? '默认规则固定在最下方，不参与拖拽排序' : '拖拽调整顺序'}">${isDefaultRule ? '🔒' : '⋮⋮'}</button>
                    </td>
                    <td><span class="service-name-cell" title="${escapeHtml(s.name || '未命名')}">${escapeHtml(s.name || '未命名')}</span></td>
                    <td><span class="service-status-badge ${enabled ? 'enabled' : 'disabled'}">${enabled ? '已开启' : '已关闭'}</span></td>
                    <td><span class="service-type-badge ${s.type}">${typeNames[s.type] || s.type}</span></td>
                    <td class="listener-services-mobile-hidden"><span class="service-domain-cell" title="${escapeHtml(s.domain || '*')}">${escapeHtml(s.domain || '*')}</span></td>
                    <td class="listener-services-mobile-hidden"><span class="service-target-cell" title="${escapeHtml(target)}">${escapeHtml(target)}</span></td>
                    <td class="service-traffic-cell services-col-stat listener-services-mobile-hidden">
                        <div class="size">${formatBytes(stats.bytes_in_total || 0)}</div>
                        <div class="speed">${formatRate(stats.bytes_in_rate || 0)}</div>
                    </td>
                    <td class="service-traffic-cell services-col-stat listener-services-mobile-hidden">
                        <div class="size">${formatBytes(stats.bytes_out_total || 0)}</div>
                        <div class="speed">${formatRate(stats.bytes_out_rate || 0)}</div>
                    </td>
                    <td class="service-conn-cell services-col-stat listener-services-mobile-hidden">${stats.active_connections ?? 0}</td>
                    <td class="service-actions-cell">
                        <button class="btn icon-btn" title="查看日志" onclick="loadServiceLogs('${s.id}', '${escapeHtml(s.name || '未命名服务')}')">📄</button>
                        <button class="btn ${enabled ? 'btn-warning' : 'btn-success'} icon-btn" title="${enabled ? '关闭规则' : '开启规则'}" onclick="toggleService('${s.id}')">${enabled ? '⏸' : '▶'}</button>
                        <button class="btn btn-primary icon-btn" title="编辑服务" onclick="editService('${s.id}')">✏️</button>
                        <button class="btn btn-danger icon-btn" title="删除服务" onclick="deleteService('${s.id}')">🗑</button>
                    </td>
                </tr>
                `;
            }).join('');
            bindServiceSortHandlers();

            if (mobileList) {
                mobileList.innerHTML = services.map(s => {
                    const enabled = s.enabled !== false;
                    const serviceName = escapeHtml(s.name || '未命名服务');
                    const serviceType = escapeHtml(typeNames[s.type] || s.type);
                    const target = escapeHtml(getServiceTarget(s) || '-');
                    const domain = escapeHtml(s.domain || '*');
                    const stats = statsMap.get(s.id) || {};
                    const bytesIn = escapeHtml(formatBytes(stats.bytes_in_total || 0));
                    const bytesOut = escapeHtml(formatBytes(stats.bytes_out_total || 0));
                    const connections = escapeHtml(String(stats.active_connections ?? 0));
                    const isDefaultRule = isDefaultServiceRule(s);
                    return `
                    <div class="listener-service-card ${enabled ? '' : 'disabled'}">
                        <div class="listener-service-card-status-corner ${enabled ? 'enabled' : 'disabled'}"></div>
                        <div class="listener-service-card-status-icon">${enabled ? '▶' : '■'}</div>
                        <div class="listener-service-card-titleline">
                            <div class="listener-service-card-name">${serviceName}</div>
                            <span class="service-type-badge ${s.type}">${serviceType}</span>
                        </div>
                        ${isDefaultRule ? '<div class="listener-service-card-default-tip">默认规则固定在列表底部</div>' : ''}
                        <div class="listener-service-card-route">
                            <div class="listener-service-card-route-item domain">${domain}</div>
                            <div class="listener-service-card-route-arrow">→</div>
                            <div class="listener-service-card-route-item target">${target}</div>
                        </div>
                        <div class="listener-service-card-stats">
                            <div class="listener-service-card-stat">
                                <div class="listener-service-card-stat-value">${bytesIn}</div>
                                <div class="listener-service-card-stat-label">入站</div>
                            </div>
                            <div class="listener-service-card-stat">
                                <div class="listener-service-card-stat-value">${bytesOut}</div>
                                <div class="listener-service-card-stat-label">出站</div>
                            </div>
                            <div class="listener-service-card-stat">
                                <div class="listener-service-card-stat-value">${connections}</div>
                                <div class="listener-service-card-stat-label">连接数</div>
                            </div>
                        </div>
                        <div class="listener-service-card-actions">
                            <button class="btn icon-btn" title="查看日志" onclick="loadServiceLogs('${s.id}', '${serviceName}')">📄</button>
                            <button class="btn ${enabled ? 'btn-warning' : 'btn-success'} icon-btn" title="${enabled ? '关闭规则' : '开启规则'}" onclick="toggleService('${s.id}')">${enabled ? '⏸' : '▶'}</button>
                            <button class="btn btn-primary icon-btn" title="编辑服务" onclick="editService('${s.id}')">✏️</button>
                            <button class="btn btn-danger icon-btn" title="删除服务" onclick="deleteService('${s.id}')">🗑</button>
                        </div>
                    </div>
                    `;
                }).join('');
            }
        }
    } catch (err) {
        console.error('Failed to load services:', err);
        if (requestToken === listenerServicesRequestToken && expectedListenerId === currentListenerId) {
            currentListenerServices = [];
            tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: #dc2626; padding: 40px;">服务数据加载失败，请稍后重试。</td></tr>';
            if (mobileList) {
                mobileList.innerHTML = '<div class="listener-service-card-empty" style="color:#dc2626;">服务数据加载失败，请稍后重试。</div>';
            }
        }
    }
}

// 获取服务目标显示
function getServiceTarget(service) {
    switch(service.type) {
        case 'reverse_proxy':
            return service.config?.upstream || '-';
        case 'static':
            return service.config?.root || '-';
        case 'redirect':
            return service.config?.to || '-';
        case 'url_jump':
            return service.config?.target_url || '-';
        case 'text_output':
            return (service.config?.body || '').substring(0, 30) || '-';
        default:
            return '-';
    }
}

// 获取服务配置摘要
function getServiceConfigSummary(service) {
    switch(service.type) {
        case 'reverse_proxy':
            return `代理: ${service.config?.upstream || '-'} | 超时: ${service.config?.timeout || 30}s`;
        case 'static':
            return `根目录: ${service.config?.root || '-'}`;
        case 'redirect':
            return `目标: ${service.config?.to || '-'}`;
        case 'url_jump':
            return `跳转: ${service.config?.target_url || '-'}`;
        case 'text_output':
            return `内容: ${(service.config?.body || '').substring(0, 30)}...`;
        default:
            return JSON.stringify(service.config || {}).substring(0, 50);
    }
}

async function loadListenerLogs(listenerId, port) {
    currentListenerLogTarget = { listenerId, port };
    currentLogDrawerContext = { type: 'listener', listenerId, port };
    openLogDrawer(`端口 ${port} 访问日志`, '展示该端口最近的访问记录');
    renderLogs('logDrawerBody', [], `正在加载端口 ${port} 的访问日志...`);

    try {
        const data = await apiRequest(`/logs/listeners/${listenerId}?limit=100`);
        if (data.success) {
            renderLogs('logDrawerBody', data.data, `端口 ${port} 暂无访问日志。`);
        } else {
            renderLogs('logDrawerBody', [], data.error || '日志加载失败');
        }
    } catch (err) {
        renderLogs('logDrawerBody', [], '日志加载失败，请稍后重试。');
    }
}

function refreshCurrentListenerLogs() {
    if (!currentListenerLogTarget) {
        renderLogs('logDrawerBody', [], '点击某个端口卡片上的日志按钮，查看该端口最近访问记录。');
        return;
    }
    loadListenerLogs(currentListenerLogTarget.listenerId, currentListenerLogTarget.port);
}

async function loadServiceLogs(serviceId, serviceName) {
    currentServiceLogTarget = { serviceId, serviceName };
    currentLogDrawerContext = { type: 'service', serviceId, serviceName };
    openLogDrawer(`${serviceName} 访问日志`, '展示该服务最近的访问记录');
    renderLogs('logDrawerBody', [], `正在加载 ${serviceName} 的访问日志...`);

    try {
        const data = await apiRequest(`/logs/services/${serviceId}?limit=100`);
        if (data.success) {
            renderLogs('logDrawerBody', data.data, `${serviceName} 暂无访问日志。`);
        } else {
            renderLogs('logDrawerBody', [], data.error || '日志加载失败');
        }
    } catch (err) {
        renderLogs('logDrawerBody', [], '日志加载失败，请稍后重试。');
    }
}

function refreshCurrentServiceLogs() {
    if (!currentServiceLogTarget) {
        renderLogs('logDrawerBody', [], '点击服务表格中的日志按钮，查看该服务最近访问记录。');
        return;
    }
    loadServiceLogs(currentServiceLogTarget.serviceId, currentServiceLogTarget.serviceName);
}

function renderDefaultServiceConfig() {
    const container = document.getElementById('defaultServiceConfig');
    if (!container) return;

    const type = defaultServiceDraft?.type;
    if (!type) {
        container.innerHTML = '';
        scheduleModalHeightUpdate();
        return;
    }

    const cfg = defaultServiceDraft.config || createServiceConfigDefaults(type);
    const isAdvanced = currentDefaultServiceMode === 'advanced';
    let configHtml = `
        <div class="mode-switch" style="margin-bottom: 16px;">
            <button type="button" class="btn ${!isAdvanced ? 'btn-primary' : ''}" onclick="toggleDefaultServiceMode('simple')">简易模式</button>
            <button type="button" class="btn ${isAdvanced ? 'btn-primary' : ''}" onclick="toggleDefaultServiceMode('advanced')">定制模式</button>
        </div>
    `;

    switch (type) {
        case 'reverse_proxy':
            configHtml += `
                <div class="form-group">
                    ${labelWithHint('代理地址 *', '反向代理的目标地址，例如 http://localhost:8080')}
                    <input type="text" id="defaultUpstream" class="form-control" value="${cfg.upstream || ''}" placeholder="http://localhost:8080">
                </div>
                <div class="form-group">
                    ${labelWithHint('超时时间(秒)', '请求转发到上游服务的超时时间')}
                    <input type="number" id="defaultTimeout" class="form-control" value="${cfg.timeout || 30}">
                </div>
            `;
            break;
        case 'static':
            configHtml += `
                <div class="form-group">
                    ${labelWithHint('根目录 *', '静态文件服务的根目录')}
                    <input type="text" id="defaultRoot" class="form-control" value="${cfg.root || ''}" placeholder="/var/www/html">
                </div>
                <div class="form-group">
                    ${checkboxLabelWithHint('启用目录浏览', '允许直接浏览目录下文件列表', 'defaultBrowse', !!cfg.browse, 'onchange="handleDefaultServiceBrowseToggle()"')}
                </div>
                ${cfg.browse ? '' : `
                <div class="form-group">
                    ${labelWithHint('首页文件', '访问目录时默认返回的文件名')}
                    <input type="text" id="defaultIndex" class="form-control" value="${cfg.index || 'index.html'}">
                </div>`}
            `;
            break;
        case 'redirect':
            configHtml += `
                <div class="form-group">
                    ${labelWithHint('目标URL *', '请求将被重定向到该地址')}
                    <input type="text" id="defaultTo" class="form-control" value="${cfg.to || ''}" placeholder="https://example.com">
                </div>
            `;
            break;
        case 'url_jump':
            configHtml += `
                <div class="form-group">
                    ${labelWithHint('跳转URL *', 'URL 跳转的目标地址')}
                    <input type="text" id="defaultTargetUrl" class="form-control" value="${cfg.target_url || ''}" placeholder="https://example.com">
                </div>
            `;
            break;
        case 'text_output':
            configHtml += `
                <div class="form-group">
                    ${labelWithHint('响应内容 *', '直接向客户端返回的文本内容')}
                    <textarea id="defaultBody" class="form-control" rows="3" placeholder="输入要返回的文本内容">${cfg.body || ''}</textarea>
                </div>
                <div class="form-group">
                    ${labelWithHint('Content-Type', '响应头里的 Content-Type 值')}
                    <input type="text" id="defaultContentType" class="form-control" value="${cfg.content_type || 'text/plain; charset=utf-8'}">
                </div>
                <div class="form-group">
                    ${labelWithHint('状态码', '返回给客户端的 HTTP 状态码')}
                    <input type="number" id="defaultStatusCode" class="form-control" value="${cfg.status_code || 200}">
                </div>
            `;
            break;
    }

    configHtml += `
        <div class="form-group" style="margin-top: 15px;">
            ${checkboxLabelWithHint('启用OAuth认证', '访问该默认规则前要求先登录', 'defaultOAuth', !!cfg.oauth)}
        </div>
        <div class="form-group">
            ${checkboxLabelWithHint('启用访问日志', '记录该默认规则的访问日志', 'defaultAccessLog', cfg.access_log !== false)}
        </div>
    `;

    if (isAdvanced) {
        configHtml += `
            <div class="form-group">
                <div class="advanced-config-header">
                    <label>高级配置 (JSON格式)</label>
                    <button type="button" class="btn btn-sm advanced-docs-toggle" onclick="showAdvancedDocsSidebar('${defaultServiceDraft.type}')">
                        📖 查看配置说明
                    </button>
                </div>
                <textarea id="defaultAdvanced" class="form-control" rows="6" placeholder='${getAdvancedConfigPlaceholder(defaultServiceDraft.type)}' onblur="validateJsonField(this)" oninput="clearJsonFieldError(this)">${defaultServiceDraft.advancedText || ''}</textarea>
                <div id="defaultAdvancedError" class="json-field-error"></div>
            </div>
        `;
    }

    container.innerHTML = configHtml;
    scheduleModalHeightUpdate();
}

function captureDefaultServiceForm() {
    if (!defaultServiceDraft) return;

    const typeSelect = document.getElementById('defaultServiceType');
    if (typeSelect) {
        defaultServiceDraft.type = typeSelect.value;
    }

    if (!defaultServiceDraft.type) {
        defaultServiceDraft.config = {};
        defaultServiceDraft.advancedText = '';
        return;
    }

    const nextConfig = createServiceConfigDefaults(defaultServiceDraft.type, defaultServiceDraft.config);
    switch (defaultServiceDraft.type) {
        case 'reverse_proxy':
            nextConfig.upstream = document.getElementById('defaultUpstream')?.value?.trim() || '';
            nextConfig.timeout = parseInt(document.getElementById('defaultTimeout')?.value, 10) || 30;
            break;
        case 'static':
            nextConfig.root = document.getElementById('defaultRoot')?.value?.trim() || '';
            nextConfig.browse = !!document.getElementById('defaultBrowse')?.checked;
            nextConfig.index = document.getElementById('defaultIndex')?.value?.trim() || nextConfig.index || 'index.html';
            break;
        case 'redirect':
            nextConfig.to = document.getElementById('defaultTo')?.value?.trim() || '';
            break;
        case 'url_jump':
            nextConfig.target_url = document.getElementById('defaultTargetUrl')?.value?.trim() || '';
            break;
        case 'text_output':
            nextConfig.body = document.getElementById('defaultBody')?.value || '';
            nextConfig.content_type = document.getElementById('defaultContentType')?.value?.trim() || 'text/plain; charset=utf-8';
            nextConfig.status_code = parseInt(document.getElementById('defaultStatusCode')?.value, 10) || 200;
            break;
    }

    nextConfig.oauth = !!document.getElementById('defaultOAuth')?.checked;
    nextConfig.access_log = !!document.getElementById('defaultAccessLog')?.checked;
    defaultServiceDraft.config = nextConfig;
    defaultServiceDraft.advancedText = document.getElementById('defaultAdvanced')?.value?.trim() || '';
}

function handleDefaultServiceTypeChange() {
    const nextType = document.getElementById('defaultServiceType').value;
    defaultServiceDraft = {
        type: nextType,
        config: createServiceConfigDefaults(nextType, defaultServiceDraft?.config || {}),
        advancedText: ''
    };
    renderDefaultServiceConfig();
}

// 显示添加监听模态框
async function showListenerModal(listener = null) {
    const isEdit = !!listener;
    setModalVariant('listener');
    document.getElementById('modalTitle').textContent = isEdit ? '编辑端口监听' : '添加端口监听';
    currentDefaultServiceMode = 'simple';
    currentDefaultServiceId = null;
    defaultServiceDraft = createDefaultServiceDraft();

    if (isEdit && listener) {
        try {
            const servicesData = await apiRequest(`/services?port_id=${listener.id}`);
            if (servicesData.success) {
                const defaultService = (servicesData.data || []).find(s => (s.domain || '*') === '*');
                if (defaultService) {
                    currentDefaultServiceId = defaultService.id;
                    defaultServiceDraft = createDefaultServiceDraft(defaultService);
                }
            }
        } catch (e) {
            console.error('Failed to load default service:', e);
            showToast('默认响应规则读取失败', 'error');
        }
    }

    document.getElementById('modalBody').innerHTML = `
        <form id="listenerForm">
            <div class="form-group">
                ${labelWithHint('端口', '监听器实际监听的端口号')}
                <input type="number" id="listenerPort" class="form-control" value="${listener?.port || ''}" required>
            </div>
            <div class="form-group">
                ${labelWithHint('协议', 'HTTP 或 HTTPS，HTTPS 会参与证书匹配')}
                <select id="listenerProtocol" class="form-control">
                    <option value="http" ${listener?.protocol === 'http' ? 'selected' : ''}>HTTP</option>
                    <option value="https" ${listener?.protocol === 'https' ? 'selected' : ''}>HTTPS</option>
                </select>
            </div>
            <hr class="divider">
            <h4 style="margin-bottom: 15px; color: #334155;">默认服务响应</h4>
            <div class="form-group">
                ${labelWithHint('默认响应类型', '当请求没有命中具体域名规则时，使用这里的默认响应')}
                <select id="defaultServiceType" class="form-control" onchange="handleDefaultServiceTypeChange()">
                    <option value="" ${!defaultServiceDraft.type ? 'selected' : ''}>无</option>
                    <option value="reverse_proxy" ${defaultServiceDraft.type === 'reverse_proxy' ? 'selected' : ''}>反向代理</option>
                    <option value="static" ${defaultServiceDraft.type === 'static' ? 'selected' : ''}>文件服务</option>
                    <option value="redirect" ${defaultServiceDraft.type === 'redirect' ? 'selected' : ''}>重定向</option>
                    <option value="url_jump" ${defaultServiceDraft.type === 'url_jump' ? 'selected' : ''}>URL跳转</option>
                    <option value="text_output" ${defaultServiceDraft.type === 'text_output' ? 'selected' : ''}>文本输出</option>
                </select>
            </div>
            <div id="defaultServiceConfig"></div>
            <div class="form-group">
                ${checkboxLabelWithHint('立即启用', '保存后立即启动该监听器', 'listenerEnabled', isEdit ? !!listener?.enabled : true)}
            </div>
        </form>
    `;

    renderDefaultServiceConfig();
    document.getElementById('modalConfirm').onclick = () => saveListener(listener?.id);
    document.getElementById('modal').classList.add('active');
    scheduleModalHeightUpdate();
}

// 切换默认服务模式
function toggleDefaultServiceMode(mode) {
    captureDefaultServiceForm();
    currentDefaultServiceMode = mode;
    renderDefaultServiceConfig();
}

// 保存端口监听
async function saveListener(id = null) {
    captureDefaultServiceForm();

    const port = parseInt(document.getElementById('listenerPort').value, 10);
    const protocol = document.getElementById('listenerProtocol').value;
    const enabled = document.getElementById('listenerEnabled').checked;

    let defaultService = null;
    if (defaultServiceDraft?.type) {
        defaultService = {
            name: '默认规则',
            type: defaultServiceDraft.type,
            domain: '*',
            enabled: true,
            config: { ...defaultServiceDraft.config }
        };

        if (defaultServiceDraft.advancedText) {
            const textarea = document.getElementById('defaultAdvanced');
            if (textarea && !validateJsonField(textarea)) {
                showToast('请修正默认响应高级配置中的 JSON 格式错误', 'error');
                textarea.focus();
                return;
            }
            try {
                const advanced = JSON.parse(defaultServiceDraft.advancedText);
                if (typeof advanced !== 'object' || advanced === null || Array.isArray(advanced)) {
                    showToast('默认响应高级配置必须是 JSON 对象格式', 'error');
                    return;
                }
                defaultService.config = { ...defaultService.config, ...advanced };
            } catch (e) {
                showToast('默认响应高级配置 JSON 格式错误：' + e.message, 'error');
                return;
            }
        }
    }

    const body = { port, protocol, enabled, default_service: !id ? defaultService : null };
    const url = id ? `/listeners/${id}` : '/listeners';
    const method = id ? 'PUT' : 'POST';

    try {
        const data = await apiRequest(url, {
            method,
            body: JSON.stringify(body)
        });
        if (!data.success) {
            showToast(data.error || '操作失败', 'error');
            return;
        }

        if (id) {
            let serviceResult = null;
            if (defaultService && currentDefaultServiceId) {
                serviceResult = await apiRequest(`/services/${currentDefaultServiceId}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        id: currentDefaultServiceId,
                        port_id: id,
                        ...defaultService
                    })
                });
            } else if (defaultService && !currentDefaultServiceId) {
                serviceResult = await apiRequest('/services', {
                    method: 'POST',
                    body: JSON.stringify({
                        port_id: id,
                        ...defaultService
                    })
                });
            } else if (!defaultService && currentDefaultServiceId) {
                serviceResult = await apiRequest(`/services/${currentDefaultServiceId}`, {
                    method: 'DELETE'
                });
            }

            if (serviceResult && !serviceResult.success) {
                showToast(serviceResult.error || '默认响应规则保存失败', 'error');
                return;
            }
        }

        closeModal();
        showToast(data.message || (isNaN(port) ? '监听保存成功' : `端口 ${port} 保存成功`), data.message ? 'info' : 'success');
        loadListeners();
        if (currentListenerId === id) {
            currentListenerPort = data.data?.port || port;
            currentListenerProtocol = data.data?.protocol || protocol;
            document.getElementById('listenerServicesTitle').textContent = `[${data.data?.port || port}]`;
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 切换监听状态
async function toggleListener(id, enable) {
    // 查找当前监听器状态
    const listenersData = await apiRequest('/listeners');
    const listener = listenersData.success ? listenersData.data.find(l => l.id === id) : null;
    const isRunning = listener?.running;
    const actionText = isRunning ? '停止' : '启动';
    const portText = listener?.port ? `端口 ${listener.port}` : '此监听';

    const confirmed = await showConfirmModal(`确定要${actionText}${portText}吗？`, {
        title: `${actionText}监听`,
        confirmText: `确认${actionText}`
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/listeners/${id}/toggle`, { method: 'POST' });
        if (data.success) {
            showToast(data.message || '端口状态已更新', data.message ? 'info' : 'success');
            loadListeners();
        } else {
            showToast(data.error || '操作失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function reloadCurrentListenerServices() {
    if (!currentListenerId) {
        showToast('当前未选中端口', 'error');
        return;
    }
    try {
        const data = await apiRequest(`/listeners/${currentListenerId}/reload`, { method: 'POST' });
        if (data.success) {
            showToast(`端口 ${currentListenerPort || ''} 服务已热重载`, 'success');
            await loadListenerServices();
        } else {
            showToast(data.error || '服务重载失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 编辑监听
async function editListener(id) {
    const data = await apiRequest('/listeners');
    if (data.success) {
        const listener = data.data.find(l => l.id === id);
        if (listener) {
            await showListenerModal(listener);
        }
    }
}

// 删除监听
async function deleteListener(id) {
    const confirmed = await showConfirmModal('确定要删除此端口监听吗？该端口下的服务配置也会一并移除。', {
        title: '删除端口监听',
        confirmText: '确认删除'
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/listeners/${id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('端口监听已删除', 'success');
            loadListeners();
        } else {
            showToast(data.error || '删除失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

function formatDateTime(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return '-';
    }
    return date.toLocaleString();
}

function formatCertificateSource(source) {
    switch (source) {
        case 'acme':
            return 'ACME';
        case 'file_sync':
            return '配置文件';
        default:
            return '导入';
    }
}

function formatCertificateChallenge(challenge) {
    if (challenge === 'dns01') return 'DNS 校验';
    if (challenge === 'http01') return '文件校验';
    return '-';
}

function formatDNSProvider(provider) {
    switch (provider) {
        case 'tencentcloud':
            return '腾讯云';
        case 'alidns':
            return '阿里云';
        case 'cloudflare':
            return 'Cloudflare';
        default:
            return '-';
    }
}

function getCertificateStatusLabel(status) {
    switch (status) {
        case 'valid':
            return '有效';
        case 'renewing':
            return '续签中';
        case 'error':
            return '异常';
        case 'expired':
            return '已过期';
        default:
            return '待处理';
    }
}

function getCertificateStatusClass(status) {
    switch (status) {
        case 'valid':
            return 'valid';
        case 'renewing':
            return 'renewing';
        case 'error':
            return 'error';
        case 'expired':
            return 'expired';
        default:
            return 'pending';
    }
}

function renderCertificateDomains(domains = []) {
    if (!domains.length) {
        return '<span style="color:#94a3b8;">-</span>';
    }
    return `<div class="cert-domain-list">${domains.map(domain => `<span class="cert-domain-tag">${escapeHtml(domain)}</span>`).join('')}</div>`;
}

async function fetchCertificateOptions(force = false) {
    if (!force && certificateOptionsCache.length) {
        return certificateOptionsCache;
    }

    const data = await apiRequest('/certificates');
    if (!data.success) {
        throw new Error(data.error || '证书列表加载失败');
    }
    certificateOptionsCache = data.data || [];
    return certificateOptionsCache;
}

function getCertificateNameById(id) {
    if (!id) return '自动匹配';
    const cert = certificateOptionsCache.find(item => item.id === id);
    return cert?.name || cert?.domains?.[0] || '已绑定证书';
}

async function loadCertificates() {
    const tbody = document.getElementById('certificatesTableBody');
    const mobileList = document.getElementById('certificatesMobileList');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#64748b; padding:32px;">正在加载证书列表...</td></tr>';
    if (mobileList) {
        mobileList.innerHTML = '<div class="certificate-mobile-card-empty">正在加载证书列表...</div>';
    }

    try {
        const certs = await fetchCertificateOptions(true);
        if (!certs.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#64748b; padding:40px;">暂无证书配置，可创建 ACME 自动续签证书或导入现有证书。</td></tr>';
            if (mobileList) {
                mobileList.innerHTML = '<div class="certificate-mobile-card-empty">暂无证书配置，可创建 ACME 自动续签证书或导入现有证书。</div>';
            }
            return;
        }

        tbody.innerHTML = certs.map(cert => `
            <tr>
                <td class="service-name-cell">${escapeHtml(cert.name || cert.domains?.[0] || '未命名证书')}</td>
                <td>${renderCertificateDomains(cert.domains || [])}</td>
                <td>${formatCertificateSource(cert.source)}</td>
                <td>${formatCertificateChallenge(cert.challenge_type)}</td>
                <td>${formatDNSProvider(cert.dns_provider)}</td>
                <td>${formatDateTime(cert.expires_at)}</td>
                <td>${formatDateTime(cert.next_renew_at)}</td>
                <td>
                    <span class="cert-status-badge ${getCertificateStatusClass(cert.status)}">${getCertificateStatusLabel(cert.status)}</span>
                    ${cert.last_error ? `<div class="cert-error-text">${escapeHtml(cert.last_error)}</div>` : ''}
                </td>
                <td class="service-actions-cell">
                    <button class="btn icon-btn" title="${cert.source === 'file_sync' ? '配置文件同步证书请修改外部配置文件' : '编辑证书'}" onclick="editCertificate('${cert.id}')">✏️</button>
                    <button class="btn ${cert.source === 'acme' ? 'btn-primary' : ''} icon-btn" title="立即续签" ${cert.source !== 'acme' ? 'disabled' : ''} onclick="renewCertificate('${cert.id}')">↻</button>
                    <button class="btn btn-danger icon-btn" title="删除证书" onclick="deleteCertificate('${cert.id}')">🗑</button>
                </td>
            </tr>
        `).join('');

        if (mobileList) {
            mobileList.innerHTML = certs.map(cert => {
                const name = escapeHtml(cert.name || cert.domains?.[0] || '未命名证书');
                const source = escapeHtml(formatCertificateSource(cert.source));
                const challenge = escapeHtml(formatCertificateChallenge(cert.challenge_type));
                const dnsProvider = escapeHtml(formatDNSProvider(cert.dns_provider));
                const expiresAt = escapeHtml(formatDateTime(cert.expires_at));
                const nextRenewAt = escapeHtml(formatDateTime(cert.next_renew_at));
                const statusLabel = escapeHtml(getCertificateStatusLabel(cert.status));
                const lastError = cert.last_error ? `<div class="cert-error-text">${escapeHtml(cert.last_error)}</div>` : '';
                return `
                <div class="certificate-mobile-card">
                    <div class="certificate-mobile-card-header">
                        <div class="certificate-mobile-card-title">
                            <div class="certificate-mobile-card-name">${name}</div>
                            <div class="certificate-mobile-card-meta">${source} / ${challenge}</div>
                        </div>
                        <div>
                            <span class="cert-status-badge ${getCertificateStatusClass(cert.status)}">${statusLabel}</span>
                        </div>
                    </div>
                    <div class="certificate-mobile-card-details">
                        <div class="certificate-mobile-card-detail">
                            <div class="certificate-mobile-card-label">域名</div>
                            <div class="certificate-mobile-card-value">${renderCertificateDomains(cert.domains || [])}</div>
                        </div>
                        <div class="certificate-mobile-card-detail">
                            <div class="certificate-mobile-card-label">DNS</div>
                            <div class="certificate-mobile-card-value">${dnsProvider}</div>
                        </div>
                        <div class="certificate-mobile-card-detail">
                            <div class="certificate-mobile-card-label">有效期</div>
                            <div class="certificate-mobile-card-value">${expiresAt}</div>
                        </div>
                        <div class="certificate-mobile-card-detail">
                            <div class="certificate-mobile-card-label">续签</div>
                            <div class="certificate-mobile-card-value">${nextRenewAt}</div>
                        </div>
                    </div>
                    ${lastError}
                    <div class="certificate-mobile-card-actions">
                        <button class="btn icon-btn" title="${cert.source === 'file_sync' ? '配置文件同步证书请修改外部配置文件' : '编辑证书'}" onclick="editCertificate('${cert.id}')">✏️</button>
                        <button class="btn ${cert.source === 'acme' ? 'btn-primary' : ''} icon-btn" title="立即续签" ${cert.source !== 'acme' ? 'disabled' : ''} onclick="renewCertificate('${cert.id}')">↻</button>
                        <button class="btn btn-danger icon-btn" title="删除证书" onclick="deleteCertificate('${cert.id}')">🗑</button>
                    </div>
                </div>
                `;
            }).join('');
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:#dc2626; padding:32px;">${escapeHtml(err.message || '网络错误，请稍后重试。')}</td></tr>`;
        if (mobileList) {
            mobileList.innerHTML = `<div class="certificate-mobile-card-empty" style="color:#dc2626;">${escapeHtml(err.message || '网络错误，请稍后重试。')}</div>`;
        }
    }
}

function getCertificateProviderFieldsHTML(provider, dnsConfig = {}) {
    switch (provider) {
        case 'tencentcloud':
            return `
                <div class="cert-provider-fields">
                    <div class="form-group">
                        ${labelWithHint('Secret ID *', '腾讯云 API 访问密钥 ID')}
                        <input type="text" id="certTencentSecretId" class="form-control" value="${escapeHtml(dnsConfig.tencent_secret_id || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Secret Key *', '腾讯云 API 访问密钥 Secret')}
                        <input type="password" id="certTencentSecretKey" class="form-control" value="${escapeHtml(dnsConfig.tencent_secret_key || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Session Token（可选）', '使用临时凭据时可填写 Session Token')}
                        <input type="password" id="certTencentSessionToken" class="form-control" value="${escapeHtml(dnsConfig.tencent_session_token || '')}">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        ${labelWithHint('Region（可选）', '腾讯云 API 调用区域，例如 ap-guangzhou')}
                        <input type="text" id="certTencentRegion" class="form-control" value="${escapeHtml(dnsConfig.tencent_region || '')}" placeholder="ap-guangzhou">
                    </div>
                </div>
            `;
        case 'alidns':
            return `
                <div class="cert-provider-fields">
                    <div class="form-group">
                        ${labelWithHint('Access Key *', '阿里云账号的 AccessKey ID')}
                        <input type="text" id="certAliAccessKey" class="form-control" value="${escapeHtml(dnsConfig.ali_access_key || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Secret Key *', '阿里云账号的 AccessKey Secret')}
                        <input type="password" id="certAliSecretKey" class="form-control" value="${escapeHtml(dnsConfig.ali_secret_key || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('STS Token（可选）', '使用 STS 临时凭据时可填写')}
                        <input type="password" id="certAliSecurityToken" class="form-control" value="${escapeHtml(dnsConfig.ali_security_token || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Region ID（可选）', 'AliDNS 使用的区域 ID，通常默认即可')}
                        <input type="text" id="certAliRegionId" class="form-control" value="${escapeHtml(dnsConfig.ali_region_id || '')}" placeholder="cn-hangzhou">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        ${labelWithHint('RAM Role（可选）', '若使用 ECS 实例 RAM 角色，可填写角色名')}
                        <input type="text" id="certAliRamRole" class="form-control" value="${escapeHtml(dnsConfig.ali_ram_role || '')}">
                    </div>
                </div>
            `;
        case 'cloudflare':
            return `
                <div class="cert-provider-fields">
                    <div class="form-group">
                        ${labelWithHint('DNS API Token *', '推荐使用具有 DNS:Edit 权限的 Cloudflare Token')}
                        <input type="password" id="certCloudflareDnsToken" class="form-control" value="${escapeHtml(dnsConfig.cloudflare_dns_api_token || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Zone Token（可选）', '如果采用拆分权限模式，可单独填写 Zone:Read Token')}
                        <input type="password" id="certCloudflareZoneToken" class="form-control" value="${escapeHtml(dnsConfig.cloudflare_zone_token || '')}">
                    </div>
                    <div class="form-group">
                        ${labelWithHint('Email（可选）', '仅在使用 Global API Key 模式时需要')}
                        <input type="email" id="certCloudflareEmail" class="form-control" value="${escapeHtml(dnsConfig.cloudflare_email || '')}">
                    </div>
                    <div class="form-group" style="margin-bottom:0;">
                        ${labelWithHint('API Key（可选）', '仅在使用 Global API Key 模式时需要')}
                        <input type="password" id="certCloudflareApiKey" class="form-control" value="${escapeHtml(dnsConfig.cloudflare_api_key || '')}">
                    </div>
                </div>
            `;
        default:
            return `<div class="form-group">${labelWithHint('DNS 凭据', '先选择 DNS 服务商，再填写对应凭据')}</div>`;
    }
}

function toggleCertificateChallengeFields() {
    const source = document.getElementById('certSource')?.value;
    const challengeGroup = document.getElementById('certChallengeGroup');
    const dnsProviderGroup = document.getElementById('certDNSProviderGroup');
    const dnsFields = document.getElementById('certDNSProviderFields');
    const renewGroup = document.getElementById('certRenewConfigGroup');
    const importGroup = document.getElementById('certImportPemGroup');

    if (!challengeGroup || !dnsProviderGroup || !dnsFields || !renewGroup || !importGroup) {
        return;
    }

    const challengeType = document.getElementById('certChallengeType')?.value || 'http01';
    const isACME = source === 'acme';

    challengeGroup.classList.toggle('hidden', !isACME);
    renewGroup.classList.toggle('hidden', !isACME);
    importGroup.classList.toggle('hidden', isACME);
    dnsProviderGroup.classList.toggle('hidden', !isACME || challengeType !== 'dns01');
    dnsFields.classList.toggle('hidden', !isACME || challengeType !== 'dns01');

    if (isACME && challengeType === 'dns01') {
        toggleCertificateProviderFields();
    } else {
        dnsFields.innerHTML = '';
    }
    scheduleModalHeightUpdate();
}

function toggleCertificateProviderFields() {
    const fields = document.getElementById('certDNSProviderFields');
    if (!fields) return;
    const provider = document.getElementById('certDNSProvider')?.value || '';
    fields.innerHTML = getCertificateProviderFieldsHTML(provider);
    scheduleModalHeightUpdate();
}

function showCertificateModal(mode = 'acme', certificate = null) {
    const isEdit = !!certificate;
    const source = certificate?.source || mode;
    const isImport = source === 'imported' || source === 'import';
    const isFileSync = source === 'file_sync';
    currentCertificateEditId = certificate?.id || null;
    if (isFileSync) {
        showToast('配置文件同步证书请修改外部证书配置文件和设置项', 'info');
        return;
    }
    setModalVariant('certificate');
    document.getElementById('modalTitle').textContent = isEdit ? '编辑证书' : (isImport ? '导入证书' : '申请证书');
    document.getElementById('modalConfirm').textContent = isEdit ? '保存' : (isImport ? '导入' : '申请');
    document.getElementById('modalBody').innerHTML = `
        <form id="certificateForm">
            <div class="form-group">
                ${labelWithHint('管理模式', 'ACME 证书支持自动签发和续签，导入证书用于接入已有证书文件')}
                <select id="certSource" class="form-control" onchange="toggleCertificateChallengeFields()" ${isEdit ? 'disabled' : ''}>
                    <option value="acme" ${!isImport ? 'selected' : ''}>ACME 自动签发/续签</option>
                    <option value="imported" ${isImport ? 'selected' : ''}>导入现有证书</option>
                </select>
            </div>
            <div class="form-group">
                ${labelWithHint('证书名称', '用于后台展示，便于区分多张证书')}
                <input type="text" id="certName" class="form-control" value="${escapeHtml(certificate?.name || '')}" placeholder="例如：官网证书 / 通配符证书">
            </div>
            <div class="form-group">
                ${labelWithHint('域名列表 *', '一行一个或用逗号分隔，HTTPS 会按这些域名自动匹配证书')}
                <textarea id="certDomains" class="form-control" rows="3" placeholder="example.com, www.example.com 或每行一个域名">${escapeHtml((certificate?.domains || []).join('\n'))}</textarea>
            </div>
            <div id="certChallengeGroup" class="form-group ${isImport ? 'hidden' : ''}">
                ${labelWithHint('校验方式', '文件校验要求 HTTP 80 可达，DNS 校验适合通配符证书')}
                <select id="certChallengeType" class="form-control" onchange="toggleCertificateChallengeFields()">
                    <option value="http01" ${certificate?.challenge_type === 'http01' || !certificate?.challenge_type ? 'selected' : ''}>文件校验（HTTP-01）</option>
                    <option value="dns01" ${certificate?.challenge_type === 'dns01' ? 'selected' : ''}>DNS 校验（DNS-01）</option>
                </select>
            </div>
            <div id="certDNSProviderGroup" class="form-group hidden">
                ${labelWithHint('DNS 服务商', '选择用于创建 TXT 验证记录的 DNS 平台')}
                <select id="certDNSProvider" class="form-control" onchange="toggleCertificateProviderFields()">
                    <option value="tencentcloud" ${certificate?.dns_provider === 'tencentcloud' ? 'selected' : ''}>腾讯云</option>
                    <option value="alidns" ${certificate?.dns_provider === 'alidns' ? 'selected' : ''}>阿里云</option>
                    <option value="cloudflare" ${certificate?.dns_provider === 'cloudflare' ? 'selected' : ''}>Cloudflare</option>
                </select>
            </div>
            <div id="certDNSProviderFields" class="form-group hidden"></div>
            <div id="certRenewConfigGroup" class="${isImport ? 'hidden' : ''}">
                <div class="form-group">
                    ${labelWithHint('账户邮箱（可选）', '用于 ACME 账户注册和证书通知')}
                    <input type="email" id="certAccountEmail" class="form-control" value="${escapeHtml(certificate?.account_email || '')}" placeholder="admin@example.com">
                </div>
                <div class="form-group">
                    ${checkboxLabelWithHint('启用自动续签', '到达续签时间后由系统自动尝试续签', 'certAutoRenew', certificate?.auto_renew ?? true)}
                </div>
                <div class="form-group">
                    ${labelWithHint('提前续签天数', '距离到期多少天时开始自动续签')}
                    <input type="number" id="certRenewBeforeDays" class="form-control" value="${certificate?.renew_before_days || 30}" min="1" max="90">
                </div>
            </div>
            <div id="certImportPemGroup" class="${isImport ? '' : 'hidden'}">
                <div class="form-group">
                    ${labelWithHint(`证书文件 ${isEdit ? '（留空则保持不变）' : '*'}`, '上传 PEM 格式证书文件')}
                    <input type="file" id="certPemFile" class="form-control" accept=".crt,.pem,.cer,.txt">
                </div>
                <div class="form-group">
                    ${labelWithHint(`私钥文件 ${isEdit ? '（留空则保持不变）' : '*'}`, '上传与证书配对的私钥文件')}
                    <input type="file" id="certKeyPemFile" class="form-control" accept=".key,.pem,.txt">
                </div>
            </div>
        </form>
    `;

    document.getElementById('modalConfirm').onclick = saveCertificate;
    document.getElementById('modal').classList.add('active');
    toggleCertificateChallengeFields();
    if (certificate?.dns_config && certificate.challenge_type === 'dns01') {
        document.getElementById('certDNSProviderFields').innerHTML = getCertificateProviderFieldsHTML(certificate.dns_provider, certificate.dns_config);
        scheduleModalHeightUpdate();
    }
}

function getCertificateRequestBody() {
    const sourceSelect = document.getElementById('certSource');
    const source = sourceSelect?.value || sourceSelect?.getAttribute('value') || 'acme';
    const challengeType = document.getElementById('certChallengeType')?.value || 'http01';
    const dnsProvider = document.getElementById('certDNSProvider')?.value || '';
    const domains = (document.getElementById('certDomains').value || '')
        .split(/[\n,]+/)
        .map(item => item.trim())
        .filter(Boolean);

    const body = {
        source,
        name: document.getElementById('certName').value.trim(),
        domains
    };

    if (source === 'acme') {
        body.challenge_type = challengeType;
        body.dns_provider = challengeType === 'dns01' ? dnsProvider : '';
        body.account_email = document.getElementById('certAccountEmail').value.trim();
        body.auto_renew = !!document.getElementById('certAutoRenew').checked;
        body.renew_before_days = parseInt(document.getElementById('certRenewBeforeDays').value || '30', 10) || 30;
        body.dns_config = {};

        if (challengeType === 'dns01') {
            switch (dnsProvider) {
                case 'tencentcloud':
                    body.dns_config.tencent_secret_id = document.getElementById('certTencentSecretId')?.value.trim() || '';
                    body.dns_config.tencent_secret_key = document.getElementById('certTencentSecretKey')?.value || '';
                    body.dns_config.tencent_session_token = document.getElementById('certTencentSessionToken')?.value || '';
                    body.dns_config.tencent_region = document.getElementById('certTencentRegion')?.value.trim() || '';
                    break;
                case 'alidns':
                    body.dns_config.ali_access_key = document.getElementById('certAliAccessKey')?.value.trim() || '';
                    body.dns_config.ali_secret_key = document.getElementById('certAliSecretKey')?.value || '';
                    body.dns_config.ali_security_token = document.getElementById('certAliSecurityToken')?.value || '';
                    body.dns_config.ali_region_id = document.getElementById('certAliRegionId')?.value.trim() || '';
                    body.dns_config.ali_ram_role = document.getElementById('certAliRamRole')?.value.trim() || '';
                    break;
                case 'cloudflare':
                    body.dns_config.cloudflare_dns_api_token = document.getElementById('certCloudflareDnsToken')?.value || '';
                    body.dns_config.cloudflare_zone_token = document.getElementById('certCloudflareZoneToken')?.value || '';
                    body.dns_config.cloudflare_email = document.getElementById('certCloudflareEmail')?.value.trim() || '';
                    body.dns_config.cloudflare_api_key = document.getElementById('certCloudflareApiKey')?.value || '';
                    break;
            }
        }
    } else {
        body.cert_pem = '';
        body.key_pem = '';
    }

    return body;
}

async function saveCertificate() {
    const body = getCertificateRequestBody();
    const isEdit = !!currentCertificateEditId;
    const certFile = document.getElementById('certPemFile')?.files?.[0] || null;
    const keyFile = document.getElementById('certKeyPemFile')?.files?.[0] || null;

    if (body.source === 'acme' && !body.domains.length) {
        showToast('请至少填写一个域名', 'error');
        return;
    }
    if (body.source === 'imported' && !isEdit && (!certFile || !keyFile)) {
        showToast('导入证书时必须上传证书文件和私钥文件', 'error');
        return;
    }
    if (body.source === 'imported' && ((certFile && !keyFile) || (!certFile && keyFile))) {
        showToast('更新导入证书时，证书文件和私钥文件需要同时上传', 'error');
        return;
    }
    if (body.source === 'acme' && body.challenge_type === 'dns01' && !body.dns_provider) {
        showToast('请选择 DNS 服务商', 'error');
        return;
    }

    try {
        let requestBody;
        if (body.source === 'imported') {
            const formData = new FormData();
            formData.append('source', body.source);
            formData.append('name', body.name);
            formData.append('domains', JSON.stringify(body.domains));
            if (certFile) formData.append('cert_file', certFile);
            if (keyFile) formData.append('key_file', keyFile);
            requestBody = formData;
        } else {
            requestBody = JSON.stringify(body);
        }

        const data = await apiRequest(isEdit ? `/certificates/${currentCertificateEditId}` : '/certificates', {
            method: isEdit ? 'PUT' : 'POST',
            body: requestBody
        });
        if (!data.success) {
            showToast(data.error || '保存证书失败', 'error');
            return;
        }

        closeModal();
        currentCertificateEditId = null;
        showToast(isEdit ? '证书已更新' : (body.source === 'imported' ? '证书已导入' : '证书申请成功'), 'success');
        loadCertificates();
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function editCertificate(id) {
    try {
        const data = await apiRequest(`/certificates/${id}`);
        if (!data.success || !data.data) {
            showToast(data.error || '加载证书详情失败', 'error');
            return;
        }
        showCertificateModal(data.data.source, data.data);
    } catch (err) {
        showToast('加载证书详情失败', 'error');
    }
}

async function renewCertificate(id) {
    const confirmed = await showConfirmModal('确认立即触发该证书的 ACME 续签吗？', {
        title: '立即续签',
        confirmText: '开始续签',
        danger: false
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/certificates/${id}/renew`, { method: 'POST' });
        if (data.success) {
            showToast('证书续签成功', 'success');
            loadCertificates();
        } else {
            showToast(data.error || '证书续签失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function deleteCertificate(id) {
    const confirmed = await showConfirmModal('删除后该证书文件也会一并移除，确认继续吗？', {
        title: '删除证书',
        confirmText: '确认删除'
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/certificates/${id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('证书已删除', 'success');
            loadCertificates();
        } else {
            showToast(data.error || '删除证书失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 加载SSH连接列表
async function loadSSHConnections() {
    try {
        const data = await apiRequest('/ssh-connections');
        const list = document.getElementById('sshConnectionsList');
        const emptyState = document.getElementById('terminalEmptyState');
        if (!data.success) {
            if (emptyState) {
                emptyState.classList.add('hidden');
            }
            list.classList.remove('hidden');
            list.innerHTML = '<div class="card">加载 SSH 连接失败</div>';
            return;
        }

        const items = data.data || [];
        sshConnectionsCache = items;
        if (!items.length) {
            list.innerHTML = '';
            list.classList.add('hidden');
            if (emptyState) {
                emptyState.classList.remove('hidden');
            }
            return;
        }

        if (emptyState) {
            emptyState.classList.add('hidden');
        }
        list.classList.remove('hidden');
        list.innerHTML = items.map(item => `
            <div class="ssh-card" onclick="openTerminalSession('${item.id}')">
                <div class="ssh-card-header">
                    <div>
                        <div class="ssh-card-title">${escapeHtml(item.name || '未命名连接')}</div>
                        <div class="ssh-card-subtitle">${item.is_local ? '本机连接' : '远程 SSH'}</div>
                    </div>
                    <div class="ssh-card-actions">
                        <button class="btn icon-btn" title="测试连接" onclick="event.stopPropagation();testSSHConnection('${item.id}')">🧪</button>
                        <button class="btn icon-btn" title="编辑连接" onclick="event.stopPropagation();showSSHConnectionModal('${item.id}')">✏️</button>
                        <button class="btn icon-btn" title="删除连接" onclick="event.stopPropagation();deleteSSHConnection('${item.id}')">🗑</button>
                    </div>
                </div>
                <div class="ssh-card-meta">
                    <div class="ssh-card-meta-row">
                        <span>地址</span>
                        <code>${escapeHtml(item.is_local ? 'localhost' : `${item.host}:${item.port || 22}`)}</code>
                    </div>
                    <div class="ssh-card-meta-row">
                        <span>用户</span>
                        <code>${escapeHtml(item.username || '-')}</code>
                    </div>
                    <div class="ssh-card-meta-row">
                        <span>工作目录</span>
                        <code>${escapeHtml(item.work_dir || '-')}</code>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        sshConnectionsCache = [];
        document.getElementById('sshConnectionsList').innerHTML = '<div class="card">网络错误，请稍后重试</div>';
    }
}

async function loadActiveTerminalSessions(showErrors = true) {
    try {
        const data = await apiRequest('/terminal-sessions');
        if (!data.success) {
            if (showErrors) {
                showToast(data.error || '加载终端会话失败', 'error');
            }
            return;
        }

        terminalSessions = data.data || [];
        renderTerminalBookmarks();
        syncTerminalModalState();
        updateTerminalHeartbeatLoop();
    } catch (err) {
        if (showErrors) {
            showToast('加载终端会话失败', 'error');
        }
    }
}

function syncTerminalModalState() {
    if (!activeTerminalSessionId) {
        return;
    }
    const session = getTerminalSession(activeTerminalSessionId);
    if (!session) {
        hideTerminalModal();
        closeTerminalSocket(false);
        activeTerminalSessionId = null;
        updateTerminalStatus(false);
    } else {
        setTerminalModalSession(session);
    }
}

function updateTerminalHeartbeatLoop() {
    if (terminalHeartbeatTimer) {
        clearInterval(terminalHeartbeatTimer);
        terminalHeartbeatTimer = null;
    }
    if (!terminalSessions.length) {
        return;
    }
    terminalHeartbeatTimer = window.setInterval(() => {
        heartbeatTerminalSessions();
    }, 20000);
}

async function heartbeatTerminalSessions() {
    if (!terminalSessions.length) {
        return;
    }
    const snapshot = [...terminalSessions];
    const results = await Promise.all(snapshot.map(session =>
        apiRequest(`/terminal-sessions/${session.id}/heartbeat`, { method: 'POST' }).catch(() => ({ success: false }))
    ));

    let changed = false;
    results.forEach((result, index) => {
        if (result.success && result.data) {
            mergeTerminalSession(result.data);
            changed = true;
        } else if (snapshot[index]) {
            terminalSessions = terminalSessions.filter(item => item.id !== snapshot[index].id);
            changed = true;
        }
    });

    if (changed) {
        renderTerminalBookmarks();
        syncTerminalModalState();
        updateTerminalHeartbeatLoop();
    }
}

function mergeTerminalSession(session) {
    const index = terminalSessions.findIndex(item => item.id === session.id);
    if (index >= 0) {
        terminalSessions[index] = session;
    } else {
        terminalSessions.push(session);
    }
}

function removeTerminalSession(sessionId) {
    terminalSessions = terminalSessions.filter(item => item.id !== sessionId);
}

function getTerminalSession(sessionId) {
    return terminalSessions.find(item => item.id === sessionId) || null;
}

function renderTerminalBookmarks() {
    const rail = document.getElementById('terminalBookmarkRail');
    if (!rail) {
        return;
    }

    if (!terminalSessions.length) {
        rail.classList.add('hidden');
        rail.innerHTML = '';
        return;
    }

    rail.classList.remove('hidden');
    rail.innerHTML = terminalSessions.map(session => `
        <button
            class="terminal-bookmark ${session.attached ? 'attached' : ''} ${session.id === activeTerminalSessionId ? 'active' : ''}"
            title="${escapeHtml(session.name || 'SSH 会话')}"
            onclick="restoreTerminalSession('${session.id}')"
        >
            <span class="terminal-bookmark-status"></span>
            <span class="terminal-bookmark-label">${escapeHtml(session.name || 'SSH')}</span>
        </button>
    `).join('');
}

async function showSSHConnectionModal(id = null) {
    let current = null;
    if (id) {
        try {
            const data = await apiRequest(`/ssh-connections/${id}`);
            if (!data.success || !data.data) {
                showToast(data.error || '读取 SSH 连接失败', 'error');
                return;
            }
            current = data.data;
        } catch (err) {
            showToast('读取 SSH 连接失败', 'error');
            return;
        }
    }

    const isEdit = !!current;
    const isLocal = current?.is_local === true;
    setModalVariant('ssh');
    document.getElementById('modalTitle').textContent = isEdit ? '编辑 SSH 连接' : '添加 SSH 连接';
    document.getElementById('modalConfirm').textContent = '保存';
    document.getElementById('modalBody').innerHTML = `
        <form id="sshConnectionForm">
            <div class="form-group">
                ${labelWithHint('连接名称', '用于区分不同 SSH 或本机终端连接')}
                <input type="text" id="sshName" class="form-control" value="${escapeHtml(current?.name || '')}" placeholder="例如：生产服务器 / 本机 PowerShell">
            </div>
            <div class="form-group">
                ${labelWithHint('连接方式', '可选择远程 SSH 或当前机器的本机终端')}
                <div class="terminal-mode-switch">
                    <button type="button" class="terminal-mode-btn ${isLocal ? '' : 'active'}" data-terminal-mode="remote">
                        <span class="terminal-mode-icon">🌐</span>
                        <span class="terminal-mode-content">
                            <span class="terminal-mode-title">远程 SSH</span>
                            <span class="terminal-mode-desc">连接到远程服务器或虚拟机</span>
                        </span>
                    </button>
                    <button type="button" class="terminal-mode-btn ${isLocal ? 'active' : ''}" data-terminal-mode="local">
                        <span class="terminal-mode-icon">💻</span>
                        <span class="terminal-mode-content">
                            <span class="terminal-mode-title">本机连接</span>
                            <span class="terminal-mode-desc">直接打开当前机器的本地终端</span>
                        </span>
                    </button>
                </div>
            </div>
            <input type="hidden" id="sshIsLocal" value="${String(isLocal)}">
            <div id="sshRemoteFields" class="${isLocal ? 'hidden' : ''}">
                <div class="form-group">
                    ${labelWithHint('IP 地址', '远程服务器的 IP 或域名')}
                    <input type="text" id="sshHost" class="form-control" value="${escapeHtml(current?.host || '')}" placeholder="例如：192.168.1.100">
                </div>
                <div class="form-group">
                    ${labelWithHint('端口', 'SSH 服务端口，默认 22')}
                    <input type="number" id="sshPort" class="form-control" value="${current?.port || 22}" min="1" max="65535">
                </div>
                <div class="form-group">
                    ${labelWithHint('用户名', '用于登录远程服务器的账号')}
                    <input type="text" id="sshUsername" class="form-control" value="${escapeHtml(current?.username || '')}" placeholder="root">
                </div>
                <div class="form-group">
                    ${labelWithHint(`密码${isEdit ? '（可选）' : ''}`, isEdit ? '留空则保持当前 SSH 密码不变' : '用于登录远程服务器的密码')}
                    <input type="password" id="sshPassword" class="form-control" placeholder="${isEdit ? '留空则保持不变' : '请输入密码'}">
                </div>
            </div>
            <div class="form-group">
                ${labelWithHint('默认工作目录（可选）', '建立终端连接后默认切换到的目录')}
                <input type="text" id="sshWorkDir" class="form-control" value="${escapeHtml(current?.work_dir || '')}" placeholder="例如：/var/www 或 C:\\Users\\fy07">
            </div>
        </form>
    `;

    document.getElementById('modal').classList.add('active');
    scheduleModalHeightUpdate();

    document.querySelectorAll('[data-terminal-mode]').forEach(btn => {
        btn.addEventListener('click', () => {
            const isLocal = btn.dataset.terminalMode === 'local';
            document.getElementById('sshIsLocal').value = String(isLocal);
            document.querySelectorAll('[data-terminal-mode]').forEach(item => item.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('sshRemoteFields').classList.toggle('hidden', isLocal);
            scheduleModalHeightUpdate();
        });
    });

    document.getElementById('sshConnectionForm').addEventListener('submit', saveSSHConnection);
    document.getElementById('modalConfirm').onclick = () => {
        document.getElementById('sshConnectionForm').requestSubmit();
    };
    document.getElementById('modalConfirm').dataset.sshEditId = id || '';
}

async function saveSSHConnection(e) {
    e.preventDefault();

    const editId = document.getElementById('modalConfirm').dataset.sshEditId || '';
    const isLocal = document.getElementById('sshIsLocal').value === 'true';
    const rawPassword = document.getElementById('sshPassword')?.value || '';
    const body = {
        name: document.getElementById('sshName').value.trim(),
        host: document.getElementById('sshHost')?.value.trim() || '',
        port: parseInt(document.getElementById('sshPort')?.value || '22', 10),
        username: document.getElementById('sshUsername')?.value.trim() || '',
        password: rawPassword,
        work_dir: document.getElementById('sshWorkDir').value.trim(),
        is_local: isLocal
    };

    if (!isLocal && (!body.host || !body.username || (!body.password && !editId))) {
        showToast('远程 SSH 连接必须填写 IP、用户名和密码', 'error');
        return;
    }

    if (rawPassword) {
        try {
            body.password = await encryptSecureValue(rawPassword);
        } catch (err) {
            showToast(err.message || 'SSH 密码加密失败', 'error');
            return;
        }
    }

    try {
        const data = await apiRequest(editId ? `/ssh-connections/${editId}` : '/ssh-connections', {
            method: editId ? 'PUT' : 'POST',
            body: JSON.stringify(body)
        });
        if (data.success) {
            closeModal();
            showToast(editId ? 'SSH 连接已更新' : 'SSH 连接已保存', 'success');
            loadSSHConnections();
        } else {
            showToast(data.error || '保存 SSH 连接失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function deleteSSHConnection(id) {
    const confirmed = await showConfirmModal('确认删除该 SSH 连接吗？', {
        title: '删除 SSH 连接',
        confirmText: '删除'
    });
    if (!confirmed) {
        return;
    }

    try {
        const data = await apiRequest(`/ssh-connections/${id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('SSH 连接已删除', 'success');
            loadSSHConnections();
        } else {
            showToast(data.error || '删除失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function testSSHConnection(id) {
    const connection = sshConnectionsCache.find(item => item.id === id);
    showSSHTestModal(connection?.name || 'SSH 连接');
    try {
        const data = await apiRequest(`/ssh-connections/${id}/test`, { method: 'POST' });
        if (data.success) {
            finishSSHTestModal(data.message || 'SSH 连接测试成功', true);
            showToast(data.message || 'SSH 连接测试成功', 'success');
        } else {
            finishSSHTestModal(data.error || 'SSH 连接测试失败', false);
            showToast(data.error || 'SSH 连接测试失败', 'error');
        }
    } catch (err) {
        finishSSHTestModal('SSH 连接测试失败', false);
        showToast('SSH 连接测试失败', 'error');
    }
}

async function openTerminalSession(connectionId) {
    const connection = sshConnectionsCache.find(item => item.id === connectionId);
    if (!connection) {
        showToast('SSH 连接不存在', 'error');
        return;
    }

    if (!initTerminalEmulator()) {
        return;
    }

    if (activeTerminalSessionId) {
        closeTerminalSocket(true);
        activeTerminalSessionId = null;
        renderTerminalBookmarks();
    }

    setTerminalModalSession(connection);
    showTerminalModal();
    clearTerminalOutput();
    updateTerminalStatus(false);
    appendTerminalOutput(`正在连接 ${connection.name || 'SSH'}...\r\n`);

    try {
        const data = await apiRequest('/terminal-sessions', {
            method: 'POST',
            body: JSON.stringify({ connection_id: connectionId })
        });
        if (!data.success || !data.data) {
            appendTerminalOutput(`\r\n[错误] ${data.error || '创建终端会话失败'}\r\n`);
            showToast(data.error || '创建终端会话失败', 'error');
            return;
        }

        mergeTerminalSession(data.data);
        renderTerminalBookmarks();
        updateTerminalHeartbeatLoop();
        activeTerminalSessionId = data.data.id;
        setTerminalModalSession(data.data);
        connectTerminalSocket(data.data.id);
        renderTerminalBookmarks();
        focusTerminalCapture();
    } catch (err) {
        appendTerminalOutput('\r\n[错误] 创建终端会话失败\r\n');
        showToast('创建终端会话失败', 'error');
    }
}

async function restoreTerminalSession(sessionId) {
    if (!getTerminalSession(sessionId)) {
        await loadActiveTerminalSessions(false);
    }
    if (!getTerminalSession(sessionId)) {
        showToast('终端会话不存在或已关闭', 'error');
        return;
    }
    await activateTerminalSession(sessionId);
}

async function activateTerminalSession(sessionId) {
    const session = getTerminalSession(sessionId);
    if (!session) {
        showToast('终端会话不存在', 'error');
        return;
    }

    if (activeTerminalSessionId === sessionId && document.getElementById('terminalSessionModal').classList.contains('active')) {
        showTerminalModal();
        focusTerminalCapture();
        return;
    }

    if (!initTerminalEmulator()) {
        return;
    }

    if (activeTerminalSessionId && activeTerminalSessionId !== sessionId) {
        closeTerminalSocket(true);
    }

    activeTerminalSessionId = sessionId;
    setTerminalModalSession(session);
    showTerminalModal();
    clearTerminalOutput();
    updateTerminalStatus(false);
    appendTerminalOutput(`正在连接 ${session.name || 'SSH'}...\r\n`);
    connectTerminalSocket(sessionId);
    renderTerminalBookmarks();
}

function initTerminalEmulator() {
    const shell = document.getElementById('terminalShell');
    const surface = document.getElementById('terminalSurface');
    const TerminalCtor = window.Terminal || window.Xterm?.Terminal;
    const FitAddonCtor = window.FitAddon?.FitAddon || window.FitAddon;

    if (!shell || !surface || !TerminalCtor || !FitAddonCtor) {
        showToast('终端控件加载失败', 'error');
        return false;
    }

    if (!terminalInstance) {
        terminalInstance = new TerminalCtor({
            cursorBlink: true,
            fontFamily: "Consolas, Monaco, 'Courier New', monospace",
            fontSize: isMobileLayout() ? 11 : 13,
            lineHeight: 1.35,
            scrollback: 3000,
            theme: {
                background: '#0f172a',
                foreground: '#dbeafe',
                cursor: '#a5b4fc',
                selectionBackground: 'rgba(99, 102, 241, 0.3)'
            }
        });
        terminalFitAddon = new FitAddonCtor();
        terminalInstance.loadAddon(terminalFitAddon);
        terminalInstance.open(surface);
        terminalInstance.onData(data => sendTerminalData(data));
        terminalInstance.onResize(size => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows }));
            }
        });
    }

    if (!terminalFocusBound) {
        window.setTimeout(() => {
            const input = surface.querySelector('.xterm-helper-textarea');
            if (input) {
                input.addEventListener('focus', () => shell.classList.add('focused'));
                input.addEventListener('blur', () => shell.classList.remove('focused'));
                terminalFocusBound = true;
            }
        }, 0);
    }

    if (!terminalResizeBound) {
        window.addEventListener('resize', fitTerminalToContainer);
        terminalResizeBound = true;
    }

    window.setTimeout(() => {
        fitTerminalToContainer();
        terminalInstance.focus();
    }, 40);
    return true;
}

function setTerminalModalSession(session) {
    document.getElementById('terminalSessionTitle').textContent = session.name || '终端管理';
    document.getElementById('terminalSessionSubtitle').textContent = session.is_local
        ? `本机连接${session.work_dir ? ` · ${session.work_dir}` : ''}`
        : `${session.username}@${session.host}:${session.port || 22}${session.work_dir ? ` · ${session.work_dir}` : ''}`;
}

function showTerminalModal() {
    document.getElementById('terminalSessionBackdrop').classList.add('active');
    document.getElementById('terminalSessionModal').classList.add('active');
    window.setTimeout(() => {
        fitTerminalToContainer();
    }, 40);
}

function hideTerminalModal() {
    document.getElementById('terminalSessionBackdrop').classList.remove('active');
    document.getElementById('terminalSessionModal').classList.remove('active');
}

async function toggleTerminalFullscreen() {
    const modal = document.getElementById('terminalSessionModal');
    if (!modal) {
        return;
    }

    try {
        if (document.fullscreenElement === modal) {
            await document.exitFullscreen();
        } else {
            await modal.requestFullscreen();
        }
    } catch (err) {
        showToast('切换全屏失败', 'error');
    }
}

function handleTerminalFullscreenChange() {
    const modal = document.getElementById('terminalSessionModal');
    const button = document.getElementById('terminalFullscreenBtn');
    if (!modal || !button) {
        return;
    }

    const isFullscreen = document.fullscreenElement === modal;
    button.textContent = isFullscreen ? '❐' : '□';
    button.title = isFullscreen ? '退出全屏' : '最大化';

    window.setTimeout(() => {
        fitTerminalToContainer();
        focusTerminalCapture();
    }, 60);
}

function connectTerminalSocket(sessionId) {
    closeTerminalSocket(false);
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws/terminal?session_id=${encodeURIComponent(sessionId)}`);

    ws.onopen = () => {
        updateTerminalStatus(true);
        focusTerminalCapture();
        terminalPingTimer = window.setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 20000);
        sendTerminalResize();
    };

    ws.onmessage = event => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'stdout' || msg.type === 'stderr') {
            appendTerminalOutput(msg.data || '');
        } else if (msg.type === 'connected') {
            updateTerminalStatus(true);
            const session = getTerminalSession(sessionId);
            if (session) {
                session.attached = true;
                session.status = msg.status || 'running';
                mergeTerminalSession(session);
                renderTerminalBookmarks();
            }
        } else if (msg.type === 'error') {
            appendTerminalOutput(`\r\n[错误] ${msg.data || '未知错误'}\r\n`);
            showToast(msg.data || '终端连接失败', 'error');
        } else if (msg.type === 'disconnected') {
            updateTerminalStatus(false);
        }
    };

    ws.onclose = () => {
        updateTerminalStatus(false);
        if (terminalPingTimer) {
            clearInterval(terminalPingTimer);
            terminalPingTimer = null;
        }
        const session = getTerminalSession(sessionId);
        if (session) {
            session.attached = false;
            mergeTerminalSession(session);
            renderTerminalBookmarks();
        }
    };

    ws.onerror = () => {
        updateTerminalStatus(false);
        appendTerminalOutput('\r\n连接发生错误\r\n');
    };
}

function focusTerminalCapture() {
    if (terminalInstance) {
        terminalInstance.focus();
    }
}

function fitTerminalToContainer() {
    if (!terminalInstance || !terminalFitAddon) {
        return;
    }
    try {
        terminalFitAddon.fit();
    } catch (err) {
    }
}

function sendTerminalResize() {
    fitTerminalToContainer();
    if (!ws || ws.readyState !== WebSocket.OPEN || !terminalInstance) {
        return;
    }
    ws.send(JSON.stringify({ type: 'resize', cols: terminalInstance.cols, rows: terminalInstance.rows }));
}

function sendTerminalData(data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
    }
}

function clearTerminalOutput() {
    if (terminalInstance) {
        terminalInstance.clear();
    }
}

function appendTerminalOutput(data) {
    if (!terminalInstance) {
        return;
    }
    terminalInstance.write(data);
}

function updateTerminalStatus(connected) {
    const badge = document.getElementById('terminalStatusBadge');
    if (!badge) {
        return;
    }
    badge.textContent = connected ? '已连接' : '未连接';
    badge.classList.toggle('disconnected', !connected);
}

function minimizeTerminalModal() {
    closeTerminalSocket(true);
    hideTerminalModal();
    activeTerminalSessionId = null;
    renderTerminalBookmarks();
    if (document.fullscreenElement === document.getElementById('terminalSessionModal')) {
        document.exitFullscreen().catch(() => {});
    }
}

async function closeTerminalModal() {
    const sessionId = activeTerminalSessionId;
    if (!sessionId) {
        hideTerminalModal();
        if (document.fullscreenElement === document.getElementById('terminalSessionModal')) {
            document.exitFullscreen().catch(() => {});
        }
        return;
    }

    closeTerminalSocket(false);
    hideTerminalModal();
    activeTerminalSessionId = null;
    if (document.fullscreenElement === document.getElementById('terminalSessionModal')) {
        document.exitFullscreen().catch(() => {});
    }

    try {
        const data = await apiRequest(`/terminal-sessions/${sessionId}`, { method: 'DELETE' });
        if (data.success) {
            removeTerminalSession(sessionId);
            renderTerminalBookmarks();
            updateTerminalHeartbeatLoop();
        } else {
            showToast(data.error || '关闭终端会话失败', 'error');
            await loadActiveTerminalSessions(false);
        }
    } catch (err) {
        showToast('关闭终端会话失败', 'error');
    }
}

function closeTerminalSocket(sendDetach = true) {
    if (terminalPingTimer) {
        clearInterval(terminalPingTimer);
        terminalPingTimer = null;
    }
    if (ws) {
        try {
            if (sendDetach && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'close' }));
            }
        } catch (err) {
        }
        ws.close();
        ws = null;
    }
    updateTerminalStatus(false);
}

// 加载用户列表
async function loadUsers() {
    try {
        const data = await apiRequest('/users');
        if (data.success) {
            const tbody = document.getElementById('usersTable');
            const mobileList = document.getElementById('usersMobileList');
            const users = data.data || [];
            usersCache = users;
            if (!users.length) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#64748b; padding:32px;">暂无用户</td></tr>';
                if (mobileList) {
                    mobileList.innerHTML = '<div class="user-mobile-card-empty">暂无用户</div>';
                }
                return;
            }
            tbody.innerHTML = users.map(u => `
                <tr class="${u.enabled === false ? 'user-disabled-row' : ''}">
                    <td>${u.username}</td>
                    <td>${u.email || '-'}</td>
                    <td><span class="user-status-badge ${u.enabled === false ? 'disabled' : 'enabled'}">${u.enabled === false ? '已禁用' : '已启用'}</span></td>
                    <td class="actions">
                        <button class="btn btn-primary icon-btn" title="编辑用户" onclick="showUserModal('${u.id}')">✏️</button>
                        <button class="btn btn-success icon-btn" title="${u.token ? '复制 token' : '未设置 token'}" onclick="copyUserToken('${u.id}')">📋</button>
                        <button class="btn ${u.enabled === false ? 'btn-success' : 'btn-warning'} icon-btn" title="${u.enabled === false ? '启用用户' : '禁用用户'}" onclick="toggleUser('${u.id}')">${u.enabled === false ? '▶' : '⏸'}</button>
                        <button class="btn btn-danger icon-btn" title="删除用户" onclick="deleteUser('${u.id}')">🗑</button>
                    </td>
                </tr>
            `).join('');
            if (mobileList) {
                mobileList.innerHTML = users.map(u => `
                    <div class="user-mobile-card ${u.enabled === false ? 'disabled' : ''}">
                        <div class="user-mobile-card-header">
                            <div>
                                <div class="user-mobile-card-name">${escapeHtml(u.username || '-')}</div>
                                <div class="user-mobile-card-email">${escapeHtml(u.email || '-')}</div>
                            </div>
                            <span class="user-status-badge ${u.enabled === false ? 'disabled' : 'enabled'}">${u.enabled === false ? '已禁用' : '已启用'}</span>
                        </div>
                        <div class="user-mobile-card-actions">
                            <button class="btn btn-primary icon-btn" title="编辑用户" onclick="showUserModal('${u.id}')">✏️</button>
                            <button class="btn btn-success icon-btn" title="${u.token ? '复制 token' : '未设置 token'}" onclick="copyUserToken('${u.id}')">📋</button>
                            <button class="btn ${u.enabled === false ? 'btn-success' : 'btn-warning'} icon-btn" title="${u.enabled === false ? '启用用户' : '禁用用户'}" onclick="toggleUser('${u.id}')">${u.enabled === false ? '▶' : '⏸'}</button>
                            <button class="btn btn-danger icon-btn" title="删除用户" onclick="deleteUser('${u.id}')">🗑</button>
                        </div>
                    </div>
                `).join('');
            }
        }
    } catch (err) {
        console.error('Failed to load users:', err);
        usersCache = [];
        const tbody = document.getElementById('usersTable');
        const mobileList = document.getElementById('usersMobileList');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#dc2626; padding:32px;">用户加载失败，请稍后重试。</td></tr>';
        }
        if (mobileList) {
            mobileList.innerHTML = '<div class="user-mobile-card-empty" style="color:#dc2626;">用户加载失败，请稍后重试。</div>';
        }
    }
}

// 显示添加用户模态框
async function showUserModal(id = null) {
    let user = null;
    if (id) {
        try {
            const data = await apiRequest('/users');
            if (!data.success) {
                showToast(data.error || '获取用户信息失败', 'error');
                return;
            }
            user = (data.data || []).find(item => item.id === id);
            if (!user) {
                showToast('用户不存在', 'error');
                return;
            }
        } catch (err) {
            showToast('获取用户信息失败', 'error');
            return;
        }
    }

    const isEdit = !!user;
    setModalVariant('user');
    document.getElementById('modalTitle').textContent = isEdit ? '编辑用户' : '添加用户';
    document.getElementById('modalConfirm').textContent = isEdit ? '保存' : '确认';
    document.getElementById('modalBody').innerHTML = `
        <form id="userForm">
            <div class="form-group">
                ${labelWithHint('用户名', '用户登录管理后台时使用的账号名')}
                <input type="text" id="userUsername" class="form-control" value="${escapeHtml(user?.username || '')}" ${isEdit ? 'disabled' : ''} required>
            </div>
            <div class="form-group">
                ${labelWithHint(`密码${isEdit ? '（可选）' : ''}`, isEdit ? '留空则保持当前密码不变' : '新用户登录密码')}
                <input type="password" id="userPassword" class="form-control" ${isEdit ? '' : 'required'}>
            </div>
            <div class="form-group">
                ${labelWithHint('Email', '用于联系或通知的邮箱地址')}
                <input type="email" id="userEmail" class="form-control" value="${escapeHtml(user?.email || '')}" placeholder="user@example.com">
            </div>
            <div class="form-group">
                ${labelWithHint(`Token${isEdit ? '（可选）' : '（可选）'}`, isEdit ? '可直接修改当前 token；留空则保持不变' : '用于请求头 Auth 鉴权，建议生成 32 位随机 token')}
                <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                    <input type="text" id="userToken" class="form-control" value="${escapeHtml(user?.token || '')}" placeholder="32位随机 token" style="flex:1; min-width:0;">
                    <button type="button" class="btn btn-primary" id="generateUserTokenBtn">生成 Token</button>
                </div>
            </div>
            <div class="form-group">
                ${checkboxLabelWithHint('是否开启', '禁用后该用户无法继续登录', 'userEnabled', user?.enabled === false ? false : true)}
            </div>
        </form>
    `;
    document.getElementById('modalConfirm').onclick = () => saveUser(id, user);
    document.getElementById('generateUserTokenBtn').onclick = () => {
        try {
            document.getElementById('userToken').value = generateRandomHexToken(32);
        } catch (err) {
            showToast(err.message || '生成 token 失败', 'error');
        }
    };
    document.getElementById('modal').classList.add('active');
    scheduleModalHeightUpdate();
}

// 保存用户
async function saveUser(id = null, currentUserRecord = null) {
    const username = currentUserRecord?.username || document.getElementById('userUsername').value;
    const rawPassword = document.getElementById('userPassword').value;
    const email = document.getElementById('userEmail').value.trim();
    const token = document.getElementById('userToken').value.trim();
    const enabled = document.getElementById('userEnabled').checked;
    const method = id ? 'PUT' : 'POST';
    const url = id ? `/users/${id}` : '/users';

    const body = {
        username,
        password: rawPassword,
        token,
        email,
        enabled,
        role: currentUserRecord?.role || 'user'
    };

    try {
        const data = await apiRequest(url, {
            method,
            body: JSON.stringify(body)
        });
        if (data.success) {
            closeModal();
            showToast(id ? '用户已更新' : '用户已创建', 'success');
            loadUsers();
        } else {
            showToast(data.error || '操作失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

async function toggleUser(id) {
    const user = usersCache.find(u => u.id === id);
    const isCurrentlyEnabled = user?.enabled !== false;
    const actionText = isCurrentlyEnabled ? '禁用' : '启用';
    const userName = user?.username || '此用户';

    // 禁用时检查是否还有其他启用用户
    if (isCurrentlyEnabled) {
        const enabledCount = usersCache.filter(u => u.enabled !== false).length;
        if (enabledCount <= 1) {
            showToast('必须保留至少一个启用状态的用户', 'error');
            return;
        }
    }

    const confirmed = await showConfirmModal(`确定要${actionText}用户「${userName}」吗？`, {
        title: `${actionText}用户`,
        confirmText: `确认${actionText}`
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/users/${id}/toggle`, { method: 'POST' });
        if (data.success) {
            showToast(data.data?.enabled === false ? '用户已禁用' : '用户已启用', 'success');
            loadUsers();
        } else {
            showToast(data.error || '切换用户状态失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 删除用户
async function deleteUser(id) {
    const user = usersCache.find(u => u.id === id);
    const userName = user?.username || '此用户';

    // 检查删除后是否还有启用用户
    const isTargetEnabled = user?.enabled !== false;
    if (isTargetEnabled) {
        const enabledCount = usersCache.filter(u => u.enabled !== false).length;
        if (enabledCount <= 1) {
            showToast('必须保留至少一个启用状态的用户，无法删除', 'error');
            return;
        }
    }

    const confirmed = await showConfirmModal(`确定要删除用户「${userName}」吗？`, {
        title: '删除用户',
        confirmText: '确认删除'
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/users/${id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('用户已删除', 'success');
            loadUsers();
        } else {
            showToast(data.error || '删除失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 加载设置
async function loadSettings() {
    try {
        const data = await apiRequest('/config');
        if (data.success) {
            document.getElementById('logRetentionDays').value = data.data.log_retention_days || 7;
            document.getElementById('maxAccessLogEntries').value = data.data.max_access_log_entries || 10000;
            document.getElementById('certificateConfigPath').value = data.data.certificate_config_path || '/usr/trim/etc/network_gateway_cert.conf';
            document.getElementById('certificateSyncIntervalSeconds').value = data.data.certificate_sync_interval_seconds || 3600;
            const effectivePaths = data.data.effective_paths || {};
            document.getElementById('effectivePidPath').value = effectivePaths.pid_path || '';
            document.getElementById('effectiveSocketPath').value = effectivePaths.socket_path || '';
            document.getElementById('effectiveCachePath').value = effectivePaths.cache_path || '';
            document.getElementById('effectiveSecurityLogsPath').value = effectivePaths.security_logs_path || '';
            document.getElementById('effectiveManagedCertsDir').value = effectivePaths.managed_certs_dir || '';
            document.getElementById('effectiveAccountCertsDir').value = effectivePaths.account_certs_dir || '';
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
    }
}

// 保存设置
async function handleSaveSettings(e) {
    e.preventDefault();

    const current = await apiRequest('/config');
    if (!current.success || !current.data) {
        showToast(current.error || '读取当前配置失败', 'error');
        return;
    }

    const config = {
        ...current.data,
        log_retention_days: parseInt(document.getElementById('logRetentionDays').value || '7', 10),
        max_access_log_entries: parseInt(document.getElementById('maxAccessLogEntries').value || '10000', 10),
        certificate_config_path: document.getElementById('certificateConfigPath').value.trim() || '/usr/trim/etc/network_gateway_cert.conf',
        certificate_sync_interval_seconds: parseInt(document.getElementById('certificateSyncIntervalSeconds').value || '3600', 10)
    };

    try {
        const data = await apiRequest('/config', {
            method: 'PUT',
            body: JSON.stringify(config)
        });
        if (data.success) {
            showToast('配置已保存', 'success');
        } else {
            showToast(data.error || '保存失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 关闭模态框
function closeModal() {
    if (modalBusy) {
        return;
    }
    const confirmButton = document.getElementById('modalConfirm');
    if (confirmButton) {
        confirmButton.textContent = '确认';
        confirmButton.onclick = null;
    }
    setModalBusy(false);
    currentCertificateEditId = null;
    resetModalHeight();
    setModalVariant('default');
    document.getElementById('modal').classList.remove('active');
}

// 显示错误
function showError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
}

// 格式化字节
function formatBytes(bytes) {
    const numeric = Number(bytes);
    if (!Number.isFinite(numeric) || numeric <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    const i = Math.max(0, Math.min(Math.floor(Math.log(numeric) / Math.log(k)), sizes.length - 1));
    return parseFloat((numeric / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function isHTTPSListenerContext() {
    return currentListenerProtocol === 'https';
}

// 显示添加服务模态框
async function showServiceModal(service = null) {
    const isEdit = !!service;
    setModalVariant('service');
    currentServiceMode = 'simple';
    currentServiceDraft = createServiceDraft(service);
    document.getElementById('modalTitle').textContent = isEdit ? '编辑服务' : '添加服务';
    document.getElementById('modalBody').innerHTML = `
        <form id="serviceForm" class="modal-form-grid">
            <div class="form-group">
                ${labelWithHint('配置模式', '简易模式适合常用配置，定制模式适合填写更多参数')}
                <div class="mode-switch">
                    <button type="button" class="btn btn-primary" id="serviceModeSimple" onclick="toggleServiceMode('simple')">简易模式</button>
                    <button type="button" class="btn" id="serviceModeAdvanced" onclick="toggleServiceMode('advanced')">定制模式</button>
                </div>
            </div>
            <div class="form-group">
                ${labelWithHint('服务名称', '用于后台展示和日志识别')}
                <input type="text" id="serviceName" class="form-control" value="${currentServiceDraft.name}" placeholder="输入服务名称">
            </div>
            <div class="form-group">
                ${labelWithHint('服务类型', '决定当前域名规则的处理方式')}
                <select id="serviceType" class="form-control" onchange="handleServiceTypeChange()">
                    <option value="reverse_proxy" ${currentServiceDraft.type === 'reverse_proxy' ? 'selected' : ''}>反向代理</option>
                    <option value="static" ${currentServiceDraft.type === 'static' ? 'selected' : ''}>静态文件服务</option>
                    <option value="redirect" ${currentServiceDraft.type === 'redirect' ? 'selected' : ''}>重定向</option>
                    <option value="url_jump" ${currentServiceDraft.type === 'url_jump' ? 'selected' : ''}>URL跳转</option>
                    <option value="text_output" ${currentServiceDraft.type === 'text_output' ? 'selected' : ''}>文本输出</option>
                </select>
            </div>
            <div id="serviceConfigFields" class="modal-span-2"></div>
            <div class="form-group modal-span-2">
                ${checkboxLabelWithHint('启用', '关闭后该域名规则不参与匹配', 'serviceEnabled', currentServiceDraft.enabled)}
            </div>
        </form>
    `;
    document.getElementById('modalConfirm').onclick = () => saveService(service?.id);
    document.getElementById('modal').classList.add('active');
    renderServiceConfigForm();
}

// 切换配置模式
function toggleServiceMode(mode) {
    captureServiceForm();
    currentServiceMode = mode;
    renderServiceConfigForm();
}

function handleServiceTypeChange() {
    const type = document.getElementById('serviceType').value;
    currentServiceDraft.type = type;
    currentServiceDraft.config = createServiceConfigDefaults(type, currentServiceDraft.config);
    currentServiceDraft.advancedText = '';
    renderServiceConfigForm();
}

function handleServiceBrowseToggle() {
    captureServiceForm();
    renderServiceConfigForm();
}

function handleDefaultServiceBrowseToggle() {
    captureDefaultServiceForm();
    renderDefaultServiceConfig();
}

function captureServiceForm() {
    if (!currentServiceDraft) return;

    currentServiceDraft.name = document.getElementById('serviceName')?.value?.trim() || '';
    currentServiceDraft.type = document.getElementById('serviceType')?.value || currentServiceDraft.type;
    currentServiceDraft.domain = document.getElementById('serviceDomain')?.value?.trim() || '';
    currentServiceDraft.certificate_id = '';
    currentServiceDraft.enabled = !!document.getElementById('serviceEnabled')?.checked;

    const nextConfig = createServiceConfigDefaults(currentServiceDraft.type, currentServiceDraft.config);
    switch (currentServiceDraft.type) {
        case 'reverse_proxy':
            nextConfig.upstream = document.getElementById('configUpstream')?.value?.trim() || '';
            nextConfig.timeout = parseInt(document.getElementById('configTimeout')?.value, 10) || 30;
            break;
        case 'static':
            nextConfig.root = document.getElementById('configRoot')?.value?.trim() || '';
            nextConfig.browse = !!document.getElementById('configBrowse')?.checked;
            nextConfig.index = document.getElementById('configIndex')?.value?.trim() || nextConfig.index || 'index.html';
            break;
        case 'redirect':
            nextConfig.to = document.getElementById('configTo')?.value?.trim() || '';
            break;
        case 'url_jump':
            nextConfig.target_url = document.getElementById('configTargetUrl')?.value?.trim() || '';
            break;
        case 'text_output':
            nextConfig.body = document.getElementById('configBody')?.value || '';
            nextConfig.content_type = document.getElementById('configContentType')?.value?.trim() || 'text/plain; charset=utf-8';
            nextConfig.status_code = parseInt(document.getElementById('configStatusCode')?.value, 10) || 200;
            break;
    }

    nextConfig.oauth = !!document.getElementById('configOAuth')?.checked;
    nextConfig.access_log = !!document.getElementById('configAccessLog')?.checked;
    currentServiceDraft.config = nextConfig;
    currentServiceDraft.advancedText = document.getElementById('configAdvanced')?.value?.trim() || '';
}

function renderServiceConfigForm() {
    const container = document.getElementById('serviceConfigFields');
    if (!container || !currentServiceDraft) return;

    document.getElementById('serviceModeSimple').className = `btn ${currentServiceMode === 'simple' ? 'btn-primary' : ''}`;
    document.getElementById('serviceModeAdvanced').className = `btn ${currentServiceMode === 'advanced' ? 'btn-primary' : ''}`;

    const cfg = currentServiceDraft.config || createServiceConfigDefaults(currentServiceDraft.type);
    const type = currentServiceDraft.type;
    const isAdvanced = currentServiceMode === 'advanced';
    container.className = 'modal-form-grid modal-span-2';

    let html = `
        <div class="form-group ${isAdvanced ? '' : 'modal-span-2'}">
            ${labelWithHint('域名 (支持*匹配)', '填写 example.com 或 *.example.com 这样的匹配规则')}
            <input type="text" id="serviceDomain" class="form-control" value="${currentServiceDraft.domain || ''}" placeholder="example.com 或 *.example.com">
        </div>
    `;

    switch (type) {
        case 'reverse_proxy':
            html += `
                <div class="form-group">
                    ${labelWithHint('代理地址', '转发请求到该上游地址')}
                    <input type="text" id="configUpstream" class="form-control" value="${cfg.upstream || ''}" placeholder="http://localhost:8080">
                </div>
                <div class="form-group">
                    ${labelWithHint('超时设置 (秒)', '请求上游服务的超时时间')}
                    <input type="number" id="configTimeout" class="form-control" value="${cfg.timeout || 30}">
                </div>
            `;
            break;
        case 'static':
            html += `
                <div class="form-group">
                    ${labelWithHint('目录地址', '静态文件服务的根目录')}
                    <input type="text" id="configRoot" class="form-control" value="${cfg.root || ''}" placeholder="/var/www/html">
                </div>
                <div class="form-group">
                    ${checkboxLabelWithHint('开启目录列表', '允许浏览目录内容', 'configBrowse', !!cfg.browse, 'onchange="handleServiceBrowseToggle()"')}
                </div>
                ${cfg.browse ? '' : `
                <div class="form-group">
                    ${labelWithHint('默认首页文件', '访问目录时默认返回的文件')}
                    <input type="text" id="configIndex" class="form-control" value="${cfg.index || 'index.html'}">
                </div>`}
            `;
            break;
        case 'redirect':
            html += `
                <div class="form-group modal-span-2">
                    ${labelWithHint('目标URL', '当前请求会被直接重定向到该地址')}
                    <input type="text" id="configTo" class="form-control" value="${cfg.to || ''}" placeholder="https://example.com/new-path">
                </div>
            `;
            break;
        case 'url_jump':
            html += `
                <div class="form-group modal-span-2">
                    ${labelWithHint('目标URL', 'URL 跳转的目标地址')}
                    <input type="text" id="configTargetUrl" class="form-control" value="${cfg.target_url || ''}" placeholder="https://example.com">
                </div>
            `;
            break;
        case 'text_output':
            html += `
                <div class="form-group modal-span-2">
                    ${labelWithHint('输出文本', '直接返回给客户端的内容')}
                    <textarea id="configBody" class="form-control" rows="4" placeholder="输入要输出的文本内容">${cfg.body || ''}</textarea>
                </div>
                <div class="form-group">
                    ${labelWithHint('Content-Type', '返回内容的 MIME 类型')}
                    <input type="text" id="configContentType" class="form-control" value="${cfg.content_type || 'text/plain; charset=utf-8'}">
                </div>
                <div class="form-group">
                    ${labelWithHint('状态码', '返回给客户端的 HTTP 状态码')}
                    <input type="number" id="configStatusCode" class="form-control" value="${cfg.status_code || 200}">
                </div>
            `;
            break;
    }

    html += `
        <div class="form-group">
            ${checkboxLabelWithHint('开启OAuth认证', '访问该服务前需要先通过登录校验', 'configOAuth', !!cfg.oauth)}
        </div>
        <div class="form-group">
            ${checkboxLabelWithHint('记录访问日志', '记录该服务的访问日志到后台', 'configAccessLog', cfg.access_log !== false)}
        </div>
    `;

    if (isAdvanced) {
        html += `
            <div class="form-group modal-span-2">
                <div class="advanced-config-header">
                    <label>高级配置 (JSON格式)</label>
                    <button type="button" class="btn btn-sm advanced-docs-toggle" onclick="showAdvancedDocsSidebar('${currentServiceDraft.type}')">
                        📖 查看配置说明
                    </button>
                </div>
                <textarea id="configAdvanced" class="form-control" rows="8" placeholder='${getAdvancedConfigPlaceholder(currentServiceDraft.type)}' onblur="validateJsonField(this)" oninput="clearJsonFieldError(this)">${currentServiceDraft.advancedText || ''}</textarea>
                <div id="configAdvancedError" class="json-field-error"></div>
            </div>
        `;
    }

    container.innerHTML = html;
    scheduleModalHeightUpdate();
}

// 保存服务
async function saveService(id = null) {
    captureServiceForm();

    let config = { ...currentServiceDraft.config };
    if (currentServiceDraft.advancedText) {
        const textarea = document.getElementById('configAdvanced');
        if (textarea && !validateJsonField(textarea)) {
            showToast('请修正高级配置中的 JSON 格式错误', 'error');
            textarea.focus();
            return;
        }
        try {
            const advanced = JSON.parse(currentServiceDraft.advancedText);
            if (typeof advanced !== 'object' || advanced === null || Array.isArray(advanced)) {
                showToast('高级配置必须是 JSON 对象格式', 'error');
                return;
            }
            config = { ...config, ...advanced };
        } catch (e) {
            showToast('高级配置 JSON 格式错误：' + e.message, 'error');
            return;
        }
    }

    const body = {
        port_id: currentListenerId,
        name: currentServiceDraft.name,
        type: currentServiceDraft.type,
        domain: currentServiceDraft.domain,
        sort_order: currentServiceDraft.sort_order,
        certificate_id: currentServiceDraft.certificate_id,
        enabled: currentServiceDraft.enabled,
        config
    };

    const url = id ? `/services/${id}` : '/services';
    const method = id ? 'PUT' : 'POST';

    try {
        const data = await apiRequest(url, { method, body: JSON.stringify(body) });
        if (data.success) {
            closeModal();
            showToast(id ? '服务已更新' : '服务已创建', 'success');
            loadListenerServices();
        } else {
            showToast(data.error || '操作失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 编辑服务
async function editService(id) {
    try {
        const data = await apiRequest(`/services/${id}`);
        if (data.success) {
            showServiceModal(data.data);
        } else {
            showToast(data.error || '获取服务信息失败', 'error');
        }
    } catch (err) {
        showToast('获取服务信息失败', 'error');
    }
}

async function toggleService(id) {
    try {
        const current = await apiRequest(`/services/${id}`);
        if (!current.success || !current.data) {
            showToast(current.error || '获取服务规则失败', 'error');
            return;
        }

        const isCurrentlyEnabled = current.data.enabled !== false;
        const actionText = isCurrentlyEnabled ? '关闭' : '开启';
        const serviceName = current.data.name || '此服务规则';

        const confirmed = await showConfirmModal(`确定要${actionText}「${serviceName}」吗？`, {
            title: `${actionText}服务规则`,
            confirmText: `确认${actionText}`
        });
        if (!confirmed) return;

        const nextEnabled = !isCurrentlyEnabled;
        const updated = await apiRequest(`/services/${id}`, {
            method: 'PUT',
            body: JSON.stringify({
                ...current.data,
                enabled: nextEnabled
            })
        });

        if (updated.success) {
            showToast(nextEnabled ? '服务规则已开启' : '服务规则已关闭', 'success');
            loadListenerServices();
        } else {
            showToast(updated.error || '切换服务状态失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 删除服务
async function deleteService(id) {
    const confirmed = await showConfirmModal('确定要删除此服务吗？删除后将立即从当前端口配置中移除。', {
        title: '删除服务',
        confirmText: '确认删除'
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest(`/services/${id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('服务已删除', 'success');
            loadListenerServices();
        } else {
            showToast(data.error || '删除失败', 'error');
        }
    } catch (err) {
        showToast('网络错误，请稍后重试', 'error');
    }
}

// 启动
init();

// 定时刷新首页数据
setInterval(() => {
    if (!document.getElementById('dashboardPage').classList.contains('hidden')) {
        loadDashboard();
    }
}, 5000);

// 显示高级配置说明侧边栏
function showAdvancedDocsSidebar(type) {
    const docsHtml = getAdvancedConfigDocs(type);
    const typeNames = {
        'reverse_proxy': '反向代理',
        'static': '静态文件服务',
        'redirect': '重定向',
        'url_jump': 'URL跳转',
        'text_output': '文本输出'
    };
    const sidebar = document.getElementById('advancedDocsSidebar');
    const title = document.getElementById('advancedDocsSidebarTitle');
    const content = document.getElementById('advancedDocsSidebarContent');
    
    if (sidebar && title && content) {
        title.textContent = `${typeNames[type] || type} 高级配置说明`;
        content.innerHTML = docsHtml;
        sidebar.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

// 关闭高级配置说明侧边栏
function closeAdvancedDocsSidebar() {
    const sidebar = document.getElementById('advancedDocsSidebar');
    if (sidebar) {
        sidebar.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// 校验 JSON 字段
function validateJsonField(textarea) {
    const value = textarea.value.trim();
    const errorEl = document.getElementById(textarea.id + 'Error');
    
    if (!value) {
        // 空值是有效的
        textarea.classList.remove('json-invalid');
        if (errorEl) errorEl.textContent = '';
        return true;
    }
    
    try {
        const parsed = JSON.parse(value);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            throw new Error('必须是 JSON 对象');
        }
        textarea.classList.remove('json-invalid');
        if (errorEl) errorEl.textContent = '';
        return true;
    } catch (e) {
        textarea.classList.add('json-invalid');
        if (errorEl) {
            let msg = 'JSON 格式错误';
            if (e.message.includes('position')) {
                const match = e.message.match(/position (\d+)/);
                if (match) {
                    msg += `（位置 ${match[1]}）`;
                }
            } else if (e.message === '必须是 JSON 对象') {
                msg = '必须是 JSON 对象格式，如 {"key": "value"}';
            }
            errorEl.textContent = msg;
        }
        return false;
    }
}

// 清除 JSON 字段错误状态
function clearJsonFieldError(textarea) {
    textarea.classList.remove('json-invalid');
    const errorEl = document.getElementById(textarea.id + 'Error');
    if (errorEl) errorEl.textContent = '';
}

// 获取高级配置说明文档
function getAdvancedConfigDocs(type) {
    if (type === 'reverse_proxy') {
        return `
<div class="docs-section">
    <h4>🔧 Host 头配置</h4>
    <div class="docs-item">
        <code>"preserve_host": true</code>
        <p>保留客户端请求的原始 Host 头发送给上游服务器</p>
    </div>
    <div class="docs-item">
        <code>"host_header": "backend.example.com"</code>
        <p>自定义发送给上游的 Host 头（优先级低于 preserve_host）</p>
    </div>
</div>
<div class="docs-section">
    <h4>🛤️ 路径处理</h4>
    <div class="docs-item">
        <code>"strip_path_prefix": "/api"</code>
        <p>去除请求路径前缀。如 /api/users → /users</p>
    </div>
    <div class="docs-item">
        <code>"add_path_prefix": "/v1"</code>
        <p>添加请求路径前缀。如 /users → /v1/users</p>
    </div>
</div>
<div class="docs-section">
    <h4>📤 请求头配置 (发送给上游)</h4>
    <div class="docs-item">
        <code>"header_up": {"X-Custom": "value", "Authorization": "Bearer token"}</code>
        <p>添加或修改发送给上游的请求头。支持变量：{host}=原始Host、{remote}=客户端IP、{scheme}=协议</p>
    </div>
    <div class="docs-item">
        <code>"hide_header_up": ["Cookie", "Authorization"]</code>
        <p>隐藏指定的请求头，不发送给上游</p>
    </div>
</div>
<div class="docs-section">
    <h4>📥 响应头配置 (返回给客户端)</h4>
    <div class="docs-item">
        <code>"header_down": {"X-Frame-Options": "DENY", "Cache-Control": "no-cache"}</code>
        <p>添加或修改返回给客户端的响应头</p>
    </div>
    <div class="docs-item">
        <code>"hide_header_down": ["Server", "X-Powered-By"]</code>
        <p>隐藏指定的响应头，不返回给客户端</p>
    </div>
</div>
<div class="docs-section">
    <h4>⚙️ 其他配置</h4>
    <div class="docs-item">
        <code>"trust_proxy_headers": true</code>
        <p>信任上游代理头（X-Forwarded-*），不覆盖已有的转发信息</p>
    </div>
    <div class="docs-item">
        <code>"timeout": 60</code>
        <p>请求超时时间（秒），默认 30 秒</p>
    </div>
</div>
<div class="docs-section docs-example">
    <h4>📋 完整示例</h4>
    <pre>{
  "preserve_host": true,
  "strip_path_prefix": "/api",
  "header_up": {
    "X-Real-Host": "{host}",
    "X-Request-ID": "req-12345"
  },
  "header_down": {
    "X-Frame-Options": "SAMEORIGIN",
    "Strict-Transport-Security": "max-age=31536000"
  },
  "hide_header_down": ["Server", "X-Powered-By"]
}</pre>
</div>`;
    }
    
    if (type === 'static') {
        return `
<div class="docs-section">
    <h4>📁 静态文件服务配置</h4>
    <div class="docs-item">
        <code>"root": "/var/www/html"</code>
        <p>静态文件根目录路径</p>
    </div>
    <div class="docs-item">
        <code>"index": "index.html"</code>
        <p>默认首页文件名</p>
    </div>
    <div class="docs-item">
        <code>"browse": true</code>
        <p>启用目录浏览功能</p>
    </div>
</div>`;
    }
    
    if (type === 'redirect' || type === 'url_jump') {
        return `
<div class="docs-section">
    <h4>🔀 重定向/跳转配置</h4>
    <div class="docs-item">
        <code>"to": "https://example.com{uri}"</code>
        <p>重定向目标地址，支持 {uri} 变量保留原始路径</p>
    </div>
    <div class="docs-item">
        <code>"preserve_path": true</code>
        <p>跳转时保留原始请求路径</p>
    </div>
</div>`;
    }
    
    if (type === 'text_output') {
        return `
<div class="docs-section">
    <h4>📝 文本输出配置</h4>
    <div class="docs-item">
        <code>"body": "Hello World"</code>
        <p>返回的文本内容</p>
    </div>
    <div class="docs-item">
        <code>"content_type": "application/json"</code>
        <p>响应的 Content-Type</p>
    </div>
    <div class="docs-item">
        <code>"status_code": 200</code>
        <p>HTTP 响应状态码</p>
    </div>
</div>`;
    }
    
    return '<p class="docs-empty">暂无该类型的高级配置说明</p>';
}

// 获取高级配置占位符
function getAdvancedConfigPlaceholder(type) {
    if (type === 'reverse_proxy') {
        return `{
  "preserve_host": true,
  "header_up": {"X-Custom": "value"},
  "header_down": {"X-Frame-Options": "DENY"}
}`;
    }
    return '{}';
}

// ======================== 安全日志 ========================

let securityLogsCurrentPage = 1;
const securityLogsPageSize = 20;

async function loadSecurityLogs(page = 1) {
    securityLogsCurrentPage = page;
    const typeFilter = document.getElementById('securityLogTypeFilter').value;
    const levelFilter = document.getElementById('securityLogLevelFilter').value;
    
    const params = new URLSearchParams({
        page: page,
        page_size: securityLogsPageSize
    });
    if (typeFilter) params.append('type', typeFilter);
    if (levelFilter) params.append('level', levelFilter);
    
    try {
        const [logsData, statsData] = await Promise.all([
            apiRequest(`/security-logs?${params}`),
            apiRequest('/security-logs/stats')
        ]);
        
        if (logsData.success) {
            renderSecurityLogs(logsData.data.logs || []);
            renderSecurityLogsPagination(logsData.data.total || 0, page);
        } else {
            showToast(logsData.error || '加载安全日志失败', 'error');
        }
        
        if (statsData.success) {
            renderSecurityLogsStats(statsData.data);
        }
    } catch (e) {
        showToast('加载安全日志失败: ' + e.message, 'error');
    }
}

function renderSecurityLogs(logs) {
    const tbody = document.getElementById('securityLogsList');
    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="security-logs-empty" style="text-align: center; color: #666;">暂无安全日志记录</td></tr>';
        return;
    }
    
    const typeLabels = {
        'oauth_login': 'OAuth登录',
        'proxy_error': '代理错误',
        'ssh_connect': 'SSH连接',
        'system_operate': '系统操作'
    };
    
    const levelLabels = {
        'info': { text: '信息', class: 'status-active' },
        'warning': { text: '警告', class: 'status-warning' },
        'error': { text: '错误', class: 'status-error' }
    };
    
    tbody.innerHTML = logs.map(log => {
        const time = new Date(log.timestamp).toLocaleString('zh-CN');
        const typeLabel = typeLabels[log.type] || log.type;
        const level = levelLabels[log.level] || { text: log.level, class: '' };
        const statusClass = log.success ? 'status-active' : 'status-error';
        const statusText = log.success ? '成功' : '失败';
        
        return `<tr>
            <td style="white-space: nowrap; font-size: 10px;">${time}</td>
            <td><span class="badge">${typeLabel}</span></td>
            <td class="security-log-col-hide-mobile"><span class="${level.class}">${level.text}</span></td>
            <td class="security-log-col-hide-mobile">${log.username || '-'}</td>
            <td class="security-log-col-hide-mobile">${log.remote_addr || '-'}</td>
            <td>${log.action || '-'}</td>
            <td class="security-log-col-hide-mobile" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(log.message)}">${escapeHtml(log.message || '-')}</td>
            <td><span class="${statusClass}">${statusText}</span></td>
        </tr>`;
    }).join('');
}

function renderSecurityLogsStats(stats) {
    const container = document.getElementById('securityLogsStats');
    if (!stats) {
        container.innerHTML = '';
        return;
    }
    
    const items = [
        { label: '总记录', value: stats.total || 0 },
        { label: 'OAuth登录', value: stats.by_type?.oauth_login || 0 },
        { label: '代理错误', value: stats.by_type?.proxy_error || 0 },
        { label: 'SSH连接', value: stats.by_type?.ssh_connect || 0 },
        { label: '系统操作', value: stats.by_type?.system_operate || 0 }
    ];
    
    container.innerHTML = items.map(item => 
        `<span style="background: #f1f5f9; padding: 4px 12px; border-radius: 6px; font-size: 13px;">${item.label}: <strong>${item.value}</strong></span>`
    ).join('');
}

function renderSecurityLogsPagination(total, currentPage) {
    const container = document.getElementById('securityLogsPagination');
    const totalPages = Math.ceil(total / securityLogsPageSize);
    
    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    let html = '';
    if (currentPage > 1) {
        html += `<button class="btn" onclick="loadSecurityLogs(${currentPage - 1})">上一页</button>`;
    }
    
    const start = Math.max(1, currentPage - 2);
    const end = Math.min(totalPages, currentPage + 2);
    
    for (let i = start; i <= end; i++) {
        if (i === currentPage) {
            html += `<button class="btn btn-primary">${i}</button>`;
        } else {
            html += `<button class="btn" onclick="loadSecurityLogs(${i})">${i}</button>`;
        }
    }
    
    if (currentPage < totalPages) {
        html += `<button class="btn" onclick="loadSecurityLogs(${currentPage + 1})">下一页</button>`;
    }
    
    container.innerHTML = html;
}

async function clearSecurityLogs() {
    const confirmed = await showConfirmModal('确定要清空所有安全日志吗？此操作不可恢复。', {
        title: '清空安全日志',
        confirmText: '确认清空'
    });
    if (!confirmed) return;

    try {
        const data = await apiRequest('/security-logs', { method: 'DELETE' });
        if (data.success) {
            showToast('安全日志已清空', 'success');
            loadSecurityLogs();
        } else {
            showToast(data.error || '清空失败', 'error');
        }
    } catch (e) {
        showToast('清空失败: ' + e.message, 'error');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
