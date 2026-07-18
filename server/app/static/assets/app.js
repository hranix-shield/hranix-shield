/* Hranix Shield — веб-панель безопасности (A-10).
   Auth (минимальный экран входа) + локализация RU/EN (data-ru/data-en,
   тот же паттерн applyLang, что в site/prototype/assets/site.js) + обзор
   и 6 консолей «Защиты» на реальных эндпоинтах /security/*. */

var TOKEN_KEY = 'hranix_shield_token';
var LANG_KEY = 'hranix-lang';

/* ---------- локализация ---------- */
function currentLang(){ return localStorage.getItem(LANG_KEY) || 'ru'; }

function applyLang(l){
  document.documentElement.lang = l;
  document.querySelectorAll('[data-ru]').forEach(function(el){
    var v = el.dataset[l]; if(v != null) el.innerHTML = v;
  });
  document.querySelectorAll('[data-ru-ph]').forEach(function(el){
    var v = el.dataset[l + 'Ph']; if(v != null) el.placeholder = v;
  });
  document.querySelectorAll('[data-ru-title]').forEach(function(el){
    var v = el.dataset[l + 'Title']; if(v != null) el.title = v;
  });
  localStorage.setItem(LANG_KEY, l);
  var langBtn = document.getElementById('langBtn');
  if(langBtn) langBtn.textContent = l === 'ru' ? 'EN' : 'RU';
  var langBtnLogin = document.getElementById('langTglLogin');
  if(langBtnLogin) langBtnLogin.textContent = l === 'ru' ? 'EN' : 'RU';

  // Re-render already-fetched dynamic content in the new language WITHOUT
  // re-fetching — the DoD requires the switch to work "without a reload",
  // and refetching on every language toggle would be wasteful/racy.
  renderHealthPill();
  if(lastOverview) renderOverview();
  if(lastConsoleId && lastConsoleData) renderConsole();
  renderNotificationsPill();
  if(lastNotifications) renderNotificationsList();
  if(lastNotifSettings) renderNotificationsSettings();
  if(lastHealthDetailed) renderHealthComponents();
  if(lastHealthLogs) renderHealthLogs();
  renderHealthFailBanner();
}
function toggleLang(){
  applyLang(currentLang() === 'ru' ? 'en' : 'ru');
}

/* API error codes (A-3 and this task's own /security/* codes) are
   translated to text ONLY here, client-side — the server only ever returns
   machine codes (§0.2 / CLAUDE.md "ЛОКАЛИЗАЦИЯ"). */
var ERROR_MESSAGES = {
  invalid_credentials: { ru: 'Неверный логин или пароль.', en: 'Incorrect username or password.' },
  account_locked: {
    ru: 'Учётная запись временно заблокирована из-за неудачных попыток входа.',
    en: 'Account temporarily locked after too many failed sign-in attempts.',
  },
  not_authenticated: { ru: 'Требуется вход.', en: 'Sign-in required.' },
  invalid_token: { ru: 'Сессия истекла — войдите снова.', en: 'Session expired — please sign in again.' },
  insufficient_role: { ru: 'Недостаточно прав.', en: 'Insufficient permissions.' },
  network_error: { ru: 'Не удалось связаться с сервером.', en: 'Could not reach the server.' },
  unknown_error: { ru: 'Неизвестная ошибка.', en: 'Unknown error.' },
  // A-11: `connector.status` values a console's real data source can report
  // (see e.g. `ids`'s CrowdSec connector) — generic codes, reused as-is by
  // any future connector-backed console (Osquery/Wazuh/ClamAV), not
  // CrowdSec-specific naming.
  connector_not_configured: {
    ru: 'Инструмент не подключён — задайте параметры подключения в .env.',
    en: 'Tool not connected — configure connection settings in .env.',
  },
  connector_unreachable: {
    ru: 'Инструмент недоступен — проверьте, что сервис запущен.',
    en: 'Tool unavailable — check that the service is running.',
  },
  connector_unauthorized: {
    ru: 'Инструмент отклонил ключ доступа — проверьте настройки.',
    en: 'Tool rejected the access key — check configuration.',
  },
  // A-18: os_firewall/os_disk_encryption can report this when the tool ran
  // but refused without elevated privileges this process must not acquire
  // wholesale (see A-18 task report) — was missing here entirely before
  // this fix, silently falling back to the generic unknown_error message.
  connector_permission_denied: {
    ru: 'Недостаточно прав для проверки — запустите с повышенными правами, если это осознанный выбор.',
    en: 'Insufficient permissions to check — run elevated if that is a deliberate choice.',
  },
};
function translateError(code){
  var entry = ERROR_MESSAGES[code] || ERROR_MESSAGES.unknown_error;
  return entry[currentLang()];
}

/* ---------- auth / API ---------- */
function authHeaders(){
  var token = localStorage.getItem(TOKEN_KEY);
  return token ? { Authorization: 'Bearer ' + token } : {};
}

/* Thin fetch wrapper: every panel request goes through here so a 401 from
   ANY endpoint (expired/invalid token) uniformly drops back to the login
   screen — callers still check `res.ok` themselves for the actual payload. */
async function apiFetch(path, options){
  options = options || {};
  var headers = Object.assign({}, options.headers || {}, authHeaders());
  if(options.body && !headers['Content-Type']){
    headers['Content-Type'] = 'application/json';
  }
  options.headers = headers;
  var res = await fetch(path, options);
  if(res.status === 401){
    localStorage.removeItem(TOKEN_KEY);
    showLogin();
  }
  return res;
}

async function handleLogin(e){
  e.preventDefault();
  var username = document.getElementById('loginUsername').value.trim();
  var password = document.getElementById('loginPassword').value;
  var errBox = document.getElementById('loginError');
  var submitBtn = document.getElementById('loginSubmit');
  errBox.hidden = true;
  submitBtn.disabled = true;
  try{
    var res = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      errBox.textContent = translateError(code);
      errBox.hidden = false;
      return false;
    }
    localStorage.setItem(TOKEN_KEY, body.access_token);
    document.getElementById('loginPassword').value = '';
    showPanel();
  } catch(err){
    errBox.textContent = translateError('network_error');
    errBox.hidden = false;
  } finally {
    submitBtn.disabled = false;
  }
  return false;
}

function handleLogout(){
  localStorage.removeItem(TOKEN_KEY);
  showLogin();
}

function showPanel(){
  document.getElementById('loginScreen').hidden = true;
  document.getElementById('panelScreen').hidden = false;
  show('view-overview');
  loadHealthPill();
  loadOverview();
  loadNotificationsPill();
  startNotificationsPolling();
  startHealthPolling();
}
function showLogin(){
  document.getElementById('panelScreen').hidden = true;
  document.getElementById('loginScreen').hidden = false;
  var pw = document.getElementById('loginPassword');
  if(pw) pw.value = '';
  lastOverview = null;
  lastConsoleId = null;
  lastConsoleData = null;
  lastNotifications = null;
  lastNotifSettings = null;
  lastHealthDetailed = null;
  lastHealthLogs = null;
  lastHealthStatus = null;
  dismissHealthFailBanner();
  stopNotificationsPolling();
  stopHealthPolling();
}
function show(viewId){
  document.querySelectorAll('.view').forEach(function(v){
    v.classList.toggle('active', v.id === viewId);
  });
}

/* ---------- значения ---------- */
function formatValue(value){
  if(value === null || value === undefined || value === '') return '—';
  if(typeof value === 'boolean'){
    return value ? (currentLang() === 'ru' ? 'Да' : 'Yes') : (currentLang() === 'ru' ? 'Нет' : 'No');
  }
  return String(value);
}
function formatTimestamp(iso){
  if(!iso) return '—';
  try{
    var date = new Date(iso);
    if(isNaN(date.getTime())) return iso;
    return date.toLocaleString(currentLang() === 'ru' ? 'ru-RU' : 'en-US', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
    });
  } catch(e){ return iso; }
}
function statusLabel(status){
  var labels = {
    ok: { ru: 'OK', en: 'OK' },
    degraded: { ru: 'Внимание', en: 'Attention' },
    down: { ru: 'Авария', en: 'Down' },
  };
  return (labels[status] || labels.ok)[currentLang()];
}

/* ---------- здоровье (пилюля + полный экран «Здоровье системы», A-14) ----------
   #healthPill сам живёт в общем <header class="topbar">, вне <main>/.view —
   поэтому он виден на любом экране панели (обзор/консоль/уведомления/здоровье)
   без какой-либо отдельной работы здесь: это уже было верно до A-14 (A-6/A-10),
   этот файл только добавляет полноценный экран за пилюлей вместо простого
   self-refresh и лёгкий поллинг для §4.7's «автоотчёт при сбое» ниже. */
var lastHealthStatus = null;      // текущий агрегированный статус (для пилюли/баннера)
var lastHealthDetailed = null;    // последний полный ответ GET /health/detailed
var lastHealthLogs = null;        // последний ответ GET /diagnostics/logs
var HEALTH_POLL_INTERVAL_MS = 20000;
var healthPollTimer = null;

function startHealthPolling(){
  stopHealthPolling();
  healthPollTimer = setInterval(loadHealthPill, HEALTH_POLL_INTERVAL_MS);
}
function stopHealthPolling(){
  if(healthPollTimer){ clearInterval(healthPollTimer); healthPollTimer = null; }
}

async function loadHealthPill(){
  try{
    var res = await apiFetch('/health/detailed');
    if(!res.ok) return;
    var body = await res.json();
    var previousStatus = lastHealthStatus;   // captured BEFORE overwriting below
    lastHealthStatus = body.status;
    lastHealthDetailed = body;
    renderHealthPill();
    if(document.getElementById('view-health') && document.getElementById('view-health').classList.contains('active')){
      renderHealthComponents();
    }
    maybeProposeDiagnosticReport(previousStatus, body.status);
  } catch(e){ /* network hiccup — pill just keeps its last known state */ }
}
function renderHealthPill(){
  var pill = document.getElementById('healthPill');
  var text = document.getElementById('healthPillText');
  if(!pill || !lastHealthStatus) return;
  pill.classList.remove('ok', 'degraded', 'down');
  pill.classList.add(lastHealthStatus);
  var labels = {
    ok: { ru: 'Здоровье · OK', en: 'Health · OK' },
    degraded: { ru: 'Здоровье · внимание', en: 'Health · degraded' },
    down: { ru: 'Здоровье · авария', en: 'Health · down' },
  };
  text.textContent = (labels[lastHealthStatus] || labels.ok)[currentLang()];
}

/* ---------- экран «Здоровье системы» (A-14) ---------- */
function openHealthScreen(){
  show('view-health');
  loadHealthPill();       // refresh + also feeds renderHealthComponents() once loaded
  loadHealthLogs();
}
function closeHealthScreen(){
  show('view-overview');
  loadOverview();
}

function switchHealthTab(tab){
  ['health', 'logs'].forEach(function(id){
    var btn = document.getElementById('healthTabBtn-' + id);
    var panel = document.getElementById('healthTab-' + id);
    if(btn) btn.classList.toggle('active', id === tab);
    if(panel) panel.classList.toggle('active', id === tab);
  });
  if(tab === 'logs') loadHealthLogs();
}

var HEALTH_COMPONENT_LABELS = {
  database: { ru: 'База данных', en: 'Database' },
  event_bus: { ru: 'Событийная шина', en: 'Event bus' },
};
function componentLabel(id){
  var known = HEALTH_COMPONENT_LABELS[id];
  if(known) return known[currentLang()];
  // Generic fallback so a future subsystem (A-11+ connectors registering
  // their own health check) renders sensibly without an app.js edit here —
  // same open-ended-registry philosophy as HealthRegistry.register itself.
  return id.replace(/_/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
}

function renderHealthComponents(){
  var box = document.getElementById('healthComponentsList');
  if(!box || !lastHealthDetailed) return;
  var components = lastHealthDetailed.components || {};
  var ids = Object.keys(components);
  box.innerHTML = '';
  if(ids.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = currentLang() === 'ru' ? 'Подсистем пока не зарегистрировано' : 'No subsystems registered yet';
    box.appendChild(empty);
    return;
  }
  ids.forEach(function(id){
    var entry = components[id] || { status: 'ok' };
    var row = document.createElement('div');
    row.className = 'con-row';

    var name = document.createElement('span');
    name.className = 'cr-k';
    name.textContent = componentLabel(id);
    row.appendChild(name);

    if(entry.error){
      var err = document.createElement('span');
      err.style.color = 'var(--ink2)';
      err.textContent = String(entry.error);
      row.appendChild(err);
    }

    var state = document.createElement('span');
    state.className = 'sec-state ' + entry.status;
    state.style.marginLeft = 'auto';
    state.textContent = statusLabel(entry.status);
    row.appendChild(state);

    box.appendChild(row);
  });
}

/* ---------- вкладка «Логи» (GET /diagnostics/logs — уже обезличенные строки A-5) ---------- */
async function loadHealthLogs(){
  var box = document.getElementById('healthLogsList');
  var level = document.getElementById('logsLevelFilter');
  try{
    var qs = '?limit=200' + (level && level.value ? '&level=' + encodeURIComponent(level.value) : '');
    var res = await apiFetch('/diagnostics/logs' + qs);
    if(!res.ok) return;
    lastHealthLogs = await res.json();
    renderHealthLogs();
  } catch(e){
    if(box) box.innerHTML = '';
  }
}
function renderHealthLogs(){
  var box = document.getElementById('healthLogsList');
  if(!box || !lastHealthLogs) return;
  var entries = lastHealthLogs.entries || [];
  box.innerHTML = '';
  if(entries.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = currentLang() === 'ru' ? 'Записей пока нет' : 'No log entries yet';
    box.appendChild(empty);
    return;
  }
  // Most recent first is the useful reading order for a live troubleshooting
  // list (unlike the bundle's own oldest-first order, meant for a written
  // report) — reverse the file's natural oldest-first order here.
  entries.slice().reverse().forEach(function(entry){
    var row = document.createElement('div');
    row.className = 'logrow';

    var ft = document.createElement('span');
    ft.className = 'ft';
    ft.textContent = entry.timestamp ? formatTimestamp(entry.timestamp) : '—';

    var lvl = document.createElement('span');
    var level = (entry.level || '').toLowerCase();
    lvl.className = 'lvl ' + (level === 'error' || level === 'critical' ? 'crit' : level === 'warning' ? 'warn' : 'ok');
    lvl.textContent = entry.level || '—';

    var logger = document.createElement('span');
    logger.className = 'lg';
    logger.textContent = entry.logger || '';

    var msg = document.createElement('span');
    msg.className = 'msg';
    msg.textContent = entry.message || '';

    row.appendChild(ft);
    row.appendChild(lvl);
    row.appendChild(logger);
    row.appendChild(msg);
    box.appendChild(row);
  });
}

/* ---------- диагностический отчёт: явное согласие + скачивание (A-14) ----------
   Единственный путь формирования бандла во всём клиенте — ничто не вызывает
   /diagnostics/bundle без прохождения через этот чек-бокс-диалог (кнопка
   «Отправить отчёт» на экране здоровья) либо через баннер сбоя ниже, который
   сам ведёт сюда же, а не скачивает напрямую — см. handleBannerGoToReport(). */
function openReportConsent(){
  var box = document.getElementById('reportConsentBox');
  var checkbox = document.getElementById('reportConsentCheckbox');
  var confirmBtn = document.getElementById('reportConfirmBtn');
  if(checkbox) checkbox.checked = false;
  if(confirmBtn) confirmBtn.disabled = true;
  setHealthReportStatus(null);
  if(box) box.hidden = false;
}
function closeReportConsent(){
  var box = document.getElementById('reportConsentBox');
  if(box) box.hidden = true;
}
function handleReportConsentToggle(){
  var checkbox = document.getElementById('reportConsentCheckbox');
  var confirmBtn = document.getElementById('reportConfirmBtn');
  if(confirmBtn) confirmBtn.disabled = !(checkbox && checkbox.checked);
}

function setHealthReportStatus(text, kind){
  var box = document.getElementById('healthReportStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

async function handleSendReport(){
  var checkbox = document.getElementById('reportConsentCheckbox');
  if(!checkbox || !checkbox.checked) return;  // consent is mandatory, button is disabled otherwise anyway
  var confirmBtn = document.getElementById('reportConfirmBtn');
  if(confirmBtn) confirmBtn.disabled = true;
  var lang = currentLang();
  try{
    var res = await apiFetch('/diagnostics/bundle');
    if(!res.ok){
      setHealthReportStatus(translateError('unknown_error'), 'error');
      return;
    }
    var blob = await res.blob();
    var url = URL.createObjectURL(blob);
    var stamp = new Date().toISOString().replace(/[:.]/g, '-');
    var a = document.createElement('a');
    a.href = url;
    a.download = 'hranix-shield-diagnostic-bundle-' + stamp + '.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    closeReportConsent();
    setHealthReportStatus(
      lang === 'ru' ? 'Отчёт сформирован и скачан.' : 'Report generated and downloaded.', 'success'
    );
  } catch(e){
    setHealthReportStatus(translateError('network_error'), 'error');
  } finally {
    if(confirmBtn) confirmBtn.disabled = !(checkbox && checkbox.checked);
  }
}

/* ---------- предложение сформировать отчёт при сбое (§4.7, A-14) ----------
   "Критический сбой" здесь трактуется как ЛЮБОЙ переход агрегированного
   здоровья из "ok" в состояние хуже ("degraded" или "down"), не только
   "down" буквально — в Фазе 0 из двух реально зарегистрированных проверок
   (database/event_bus, см. services/health/checks.py) БД-проверка по
   собственному дизайну A-6 никогда не возвращает хуже "degraded" (см. её
   комментарий: сбой БД — это degraded, никогда 500/DOWN), так что живой
   демонстрируемый сценарий сбоя в этой фазе — именно "ok → degraded"; трактовка
   только "down" сделала бы это предложение практически недостижимым при любом
   реалистичном сбое, который Фаза 0 вообще умеет показывать. См. отчёт по
   задаче A-14. Срабатывает только на ПЕРЕХОД (не на каждый последующий опрос,
   пока сбой длится) — то же правило, что уже применяет HealthRegistry для
   события health.changed на сервере. Ничего не отправляется/не формируется
   автоматически — только показывает баннер с предложением перейти к тому же
   согласованному диалогу, что и ручная кнопка «Отправить отчёт» выше. */
// Holds the status the banner is CURRENTLY showing (not re-derived from
// `lastHealthStatus` at render time) — deliberately self-contained: a
// subsequent poll can move `lastHealthStatus` again (e.g. down -> degraded)
// without re-triggering `maybeProposeDiagnosticReport`'s "ok -> bad" edge
// detection, and this variable is what a lang toggle's `renderHealthFailBanner()`
// re-renders from, so the banner's text never drifts from what the user was
// actually shown just because some unrelated state moved on in the background.
var healthFailBannerStatus = null;
function maybeProposeDiagnosticReport(previousStatus, newStatus){
  if(previousStatus === 'ok' && newStatus !== 'ok'){
    showHealthFailBanner(newStatus);
  } else if(newStatus === 'ok' && healthFailBannerStatus){
    dismissHealthFailBanner();
  }
}
function showHealthFailBanner(status){
  var banner = document.getElementById('healthFailBanner');
  var msg = document.getElementById('healthFailBannerMsg');
  if(!banner) return;
  healthFailBannerStatus = status;
  if(msg){
    msg.textContent = currentLang() === 'ru'
      ? 'Обнаружен сбой в работе платформы (здоровье: ' + statusLabel(status) + '). Ничего не отправляется автоматически.'
      : 'A platform failure was detected (health: ' + statusLabel(status) + '). Nothing is sent automatically.';
  }
  banner.hidden = false;
}
function renderHealthFailBanner(){
  // Re-applies the current banner text in the new language on a lang
  // toggle, without re-deciding whether it should be showing.
  if(healthFailBannerStatus) showHealthFailBanner(healthFailBannerStatus);
}
function dismissHealthFailBanner(){
  healthFailBannerStatus = null;
  var banner = document.getElementById('healthFailBanner');
  if(banner) banner.hidden = true;
}
function handleBannerGoToReport(){
  dismissHealthFailBanner();
  openHealthScreen();
  switchHealthTab('health');
  openReportConsent();
}

/* ---------- щит консолей защиты (агрегат из /security/overview) ----------
   Отдельный индикатор от #healthPill: тот отражает здоровье ПРИЛОЖЕНИЯ
   (БД/event bus, A-6/`/health/detailed`) и не меняется от переключения
   консолей — щит здесь специально питается от `lastOverview.status`
   (worst-of-all 6 консолей, §6.2 плана: "агрегируется в общий щит"). */
var SECURITY_SHIELD_LABELS = {
  ok: { ru: '🛡️ Защита · OK', en: '🛡️ Protection · OK' },
  degraded: { ru: '🛡️ Защита · внимание', en: '🛡️ Protection · degraded' },
  down: { ru: '🛡️ Защита · авария', en: '🛡️ Protection · down' },
};
function renderSecurityShieldPill(){
  var pill = document.getElementById('securityShieldPill');
  var text = document.getElementById('securityShieldPillText');
  if(!pill || !lastOverview) return;
  var status = lastOverview.status || 'ok';
  pill.classList.remove('ok', 'degraded', 'down');
  pill.classList.add(status);
  text.textContent = (SECURITY_SHIELD_LABELS[status] || SECURITY_SHIELD_LABELS.ok)[currentLang()];
}

/* ---------- метаданные консолей (только текстовые метки/иконки — все
   значения приходят с бэкенда, ничего числового здесь не хардкодится) ---------- */
var CONSOLE_ORDER = ['perimeter', 'ids', 'av', 'network', 'backup', 'logs'];

var TOOL_LABELS = {
  os_firewall: 'OS Firewall', bitlocker_filevault: 'BitLocker / FileVault',
  crowdsec_bouncer: 'CrowdSec bouncer', crowdsec: 'CrowdSec', osquery: 'Osquery',
  wazuh: 'Wazuh', clamav: 'ClamAV', yara: 'YARA', defender_xprotect: 'Defender / XProtect',
  os_counters: 'OS counters', pgbackrest: 'pgBackRest', restic: 'restic',
  wazuh_agent: 'Wazuh Agent', windows_event_log: 'Windows Event Log',
  macos_unified_log: 'macOS Unified Log',
};

var CONSOLE_META = {
  perimeter: {
    icon: '🛡️',
    title: { ru: 'Защита периметра', en: 'Perimeter protection' },
    metricLabels: {
      firewall_active: { ru: 'Фаервол', en: 'Firewall' },
      disk_encryption_active: { ru: 'Шифрование дисков', en: 'Disk encryption' },
      open_ports: { ru: 'Открытых портов', en: 'Open ports' },
      firewall_rules: { ru: 'Правил фаервола', en: 'Firewall rules' },
    },
    chartTitle: { ru: 'Заблокировано входящих · 24 часа', en: 'Blocked incoming · 24h' },
    actions: [
      { ru: '🔒 Заблокировать все входящие', en: '🔒 Block all incoming' },
      { ru: 'Пересканировать порты', en: 'Rescan ports' },
      { ru: 'Правила фаервола', en: 'Firewall rules' },
    ],
    settingLabels: {
      protection_profile: { ru: 'Профиль защиты', en: 'Protection profile' },
      auto_block_new_incoming: { ru: 'Автоблокировка новых входящих', en: 'Auto-block new incoming' },
      notify_new_open_ports: { ru: 'Уведомлять о новых открытых портах', en: 'Notify on new open ports' },
      require_vpn_outside_trusted: { ru: 'Требовать VPN вне доверенной сети', en: 'Require VPN outside trusted network' },
    },
  },
  ids: {
    icon: '🛰️',
    title: { ru: 'Обнаружение вторжений', en: 'Intrusion detection' },
    metricLabels: {
      banned_24h: { ru: 'Забанено за 24ч', en: 'Banned in 24h' },
      active_bans: { ru: 'Активных банов', en: 'Active bans' },
      scenarios: { ru: 'Сценариев (правил)', en: 'Scenarios (rules)' },
      last_event_at: { ru: 'Последнее событие', en: 'Last event' },
    },
    chartTitle: { ru: 'Попытки вторжений · 7 дней', en: 'Intrusion attempts · 7 days' },
    listKey: 'recent_attempts',
    listTitle: { ru: 'Последние попытки', en: 'Recent attempts' },
    actions: [
      { ru: 'Разбанить IP', en: 'Unban IP' },
      { ru: 'Забанить вручную', en: 'Ban manually' },
      { ru: 'Обновить сценарии', en: 'Update scenarios' },
    ],
    settingLabels: {
      ban_threshold: { ru: 'Порог бана', en: 'Ban threshold' },
      ban_duration_hours: { ru: 'Длительность бана (ч)', en: 'Ban duration (h)' },
      whitelist_count: { ru: 'Белый список (адресов)', en: 'Whitelist (addresses)' },
      rule_source: { ru: 'Источник правил', en: 'Rule source' },
    },
  },
  av: {
    icon: '🦠',
    title: { ru: 'Вирусная активность', en: 'Virus activity' },
    metricLabels: {
      clean: { ru: 'Угроз не найдено', en: 'No threats found' },
      last_scan_at: { ru: 'Последняя проверка', en: 'Last scan' },
      quarantine_count: { ru: 'В карантине', en: 'In quarantine' },
      databases_updated_at: { ru: 'Базы обновлены', en: 'Databases updated' },
    },
    chartTitle: { ru: 'Проверено файлов · 7 дней', en: 'Files scanned · 7 days' },
    actions: [
      { ru: 'Быстрая проверка', en: 'Quick scan' },
      { ru: 'Полная проверка', en: 'Full scan' },
      { ru: 'Обновить базы', en: 'Update databases' },
      { ru: 'Карантин', en: 'Quarantine' },
    ],
    settingLabels: {
      realtime_protection: { ru: 'Защита в реальном времени', en: 'Real-time protection' },
      scan_schedule: { ru: 'Расписание проверок', en: 'Scan schedule' },
      action_on_threat: { ru: 'Действие при угрозе', en: 'Action on threat' },
      scan_removable_media: { ru: 'Проверять съёмные носители', en: 'Scan removable media' },
    },
  },
  network: {
    icon: '📡',
    title: { ru: 'Сеть', en: 'Network' },
    metricLabels: {
      outbound_traffic_status: { ru: 'Исходящий трафик', en: 'Outbound traffic' },
      active_connections: { ru: 'Активных соединений', en: 'Active connections' },
      suspicious_connections: { ru: 'Подозрительных', en: 'Suspicious' },
      dns_leak_detected: { ru: 'Утечка DNS', en: 'DNS leak' },
    },
    chartTitle: { ru: 'Трафик · последний час', en: 'Traffic · last hour' },
    listKey: 'connections',
    listTitle: { ru: 'Активные соединения', en: 'Active connections' },
    actions: [
      { ru: 'Разорвать соединение', en: 'Disconnect' },
      { ru: 'Блокировать процесс', en: 'Block process' },
      { ru: 'Экспорт журнала', en: 'Export log' },
    ],
    settingLabels: {
      monitor_outbound: { ru: 'Мониторинг исходящего трафика', en: 'Monitor outbound traffic' },
      alert_on_anomalies: { ru: 'Оповещать об аномалиях', en: 'Alert on anomalies' },
      block_unknown_outbound: { ru: 'Блокировать неизвестные исходящие', en: 'Block unknown outbound' },
      dns_over_https: { ru: 'DNS-over-HTTPS', en: 'DNS-over-HTTPS' },
    },
  },
  backup: {
    icon: '💾',
    title: { ru: 'Резервные копии', en: 'Backups' },
    metricLabels: {
      last_backup_at: { ru: 'Последняя копия', en: 'Last backup' },
      last_backup_status: { ru: 'Статус последней копии', en: 'Last backup status' },
      total_size_bytes: { ru: 'Объём копий (байт)', en: 'Total backup size (bytes)' },
      storages: { ru: 'Хранилищ', en: 'Storage targets' },
      next_scheduled_at: { ru: 'Следующая по расписанию', en: 'Next scheduled' },
    },
    chartTitle: { ru: 'Объём копий · 7 дней', en: 'Backup size · 7 days' },
    listKey: 'modules',
    listTitle: { ru: 'Модули системы', en: 'System modules' },
    actions: [
      { id: 'create_snapshot', ru: '💾 Создать полную копию', en: '💾 Create full backup' },
      { id: 'restore_system', ru: 'Восстановить систему…', en: 'Restore system…' },
      // No `id` (yet): unlike the two above, there is no external-storage
      // target implemented in Phase 0 (§7.1 wants >=2 storages, local +
      // NAS/external — not built) — this one stays a disabled placeholder
      // like every action on the other 5 consoles.
      { ru: 'Экспорт во внешнее хранилище', en: 'Export to external storage' },
    ],
    settingLabels: {
      schedule: { ru: 'Расписание копий', en: 'Backup schedule' },
      retention: { ru: 'Хранить копии', en: 'Retention' },
      encryption: { ru: 'Шифрование копий', en: 'Backup encryption' },
      auto_restore_on_corruption: { ru: 'Автовосстановление после сбоя', en: 'Auto-restore on corruption' },
    },
  },
  logs: {
    icon: '📋',
    title: { ru: 'Журналы ОС', en: 'OS logs' },
    metricLabels: {
      events_24h: { ru: 'Событий за сутки', en: 'Events (24h)' },
      warnings_24h: { ru: 'Предупреждений', en: 'Warnings' },
      security_errors_24h: { ru: 'Ошибки безопасности', en: 'Security errors' },
      sources: { ru: 'Источников журналов', en: 'Log sources' },
    },
    chartTitle: { ru: 'События безопасности · 7 дней', en: 'Security events · 7 days' },
    listKey: 'entries',
    listTitle: { ru: 'Журнал событий', en: 'Event log' },
    actions: [
      {
        ru: '🤖 Анализ ассистентом', en: '🤖 Assistant analysis', soon: true,
        tipRu: 'Скоро — требует ИИ-ассистента (Фаза 2+), не реализовано в Фазе 0',
        tipEn: 'Coming soon — requires the AI assistant (Phase 2+), not implemented in Phase 0',
      },
      { ru: 'Экспорт журнала', en: 'Export log' },
    ],
    settingLabels: {
      os_event_log: { ru: 'Журнал событий Windows / unified log macOS', en: 'Windows Event Log / macOS unified log' },
      audit_logins_privilege: { ru: 'Аудит входов и повышения прав', en: 'Audit logins and privilege escalation' },
      wazuh_crowdsec_events: { ru: 'События Wazuh / CrowdSec', en: 'Wazuh / CrowdSec events' },
      sysmon: { ru: 'Sysmon (Windows)', en: 'Sysmon (Windows)' },
      retention_days: { ru: 'Хранить журналы (дней)', en: 'Retain logs (days)' },
    },
  },
};

// Backup's "modules" list (unlike the other consoles' recent_attempts/
// connections/entries) is the one list Phase 0 actually populates with
// non-empty placeholder rows (see routers/security_console.py), so it is
// worth a dedicated, readable rendering — see renderConsoleList() below.
var MODULE_LABELS = {
  database: { ru: 'База данных', en: 'Database' },
  documents: { ru: 'Документы', en: 'Documents' },
  knowledge_rag: { ru: 'Знания · RAG-индекс', en: 'Knowledge · RAG index' },
  experience: { ru: 'Накопленный опыт', en: 'Accumulated experience' },
  crm: { ru: 'CRM', en: 'CRM' },
  tasks_calendar: { ru: 'Задачи и календарь', en: 'Tasks & calendar' },
  settings_plugins: { ru: 'Настройки и плагины', en: 'Settings & plugins' },
};

var CONSOLE_ROUTES = {
  perimeter: '/security/consoles/perimeter',
  ids: '/security/consoles/ids',
  av: '/security/consoles/av',
  network: '/security/consoles/network',
  backup: '/security/consoles/backup',
  logs: '/security/consoles/logs',
};

/* ---------- обзор ---------- */
var lastOverview = null;

async function loadOverview(){
  try{
    var res = await apiFetch('/security/overview');
    if(!res.ok) return;
    lastOverview = await res.json();
    renderOverview();
  } catch(e){ /* network hiccup — overview just keeps showing the last snapshot */ }
}

var KPI_META = [
  { key: 'blocked_24h', ru: 'Заблокировано за сутки', en: 'Blocked in 24h' },
  { key: 'active_connections', ru: 'Активных соединений', en: 'Active connections' },
  { key: 'system_load_pct', ru: 'Нагрузка системы', en: 'System load' },
  { key: 'uptime_pct', ru: 'Аптайм защиты', en: 'Protection uptime' },
];

function renderOverview(){
  if(!lastOverview) return;
  renderSecurityShieldPill();
  renderKpis();
  renderSecCards();
  renderEventLog();
}

function renderKpis(){
  var box = document.getElementById('secKpis');
  if(!box) return;
  box.innerHTML = '';
  var kpis = lastOverview.kpis || {};
  KPI_META.forEach(function(meta){
    var tile = document.createElement('div');
    tile.className = 'kpi';
    var n = document.createElement('span');
    n.className = 'kpi-n';
    n.textContent = formatValue(kpis[meta.key]);
    var l = document.createElement('div');
    l.className = 'kpi-l';
    l.textContent = meta[currentLang()];
    tile.appendChild(n);
    tile.appendChild(l);
    box.appendChild(tile);
  });
}

function renderSecCards(){
  var box = document.getElementById('secCards');
  if(!box) return;
  box.innerHTML = '';
  var consoles = lastOverview.consoles || {};
  var lang = currentLang();
  CONSOLE_ORDER.forEach(function(id){
    var meta = CONSOLE_META[id];
    var entry = consoles[id] || { status: 'ok', enabled: true };
    var btn = document.createElement('button');
    btn.className = 'sec-card ' + entry.status;
    btn.type = 'button';
    btn.onclick = function(){ openConsole(id); };

    var ic = document.createElement('div');
    ic.className = 'sec-ic';
    ic.textContent = meta.icon;

    var body = document.createElement('div');
    body.className = 'sec-cbody';
    var title = document.createElement('b');
    title.textContent = meta.title[lang];
    var sub = document.createElement('span');
    sub.textContent = entry.enabled
      ? (lang === 'ru' ? 'включена' : 'enabled')
      : (lang === 'ru' ? 'выключена' : 'disabled');
    body.appendChild(title);
    body.appendChild(sub);

    var state = document.createElement('span');
    state.className = 'sec-state ' + entry.status;
    state.textContent = statusLabel(entry.status);

    var go = document.createElement('span');
    go.className = 'sec-go';
    go.textContent = '›';

    btn.appendChild(ic);
    btn.appendChild(body);
    btn.appendChild(state);
    btn.appendChild(go);
    box.appendChild(btn);
  });
}

var EVENT_TOPIC_LABELS = {
  'security.alert': { ru: 'Безопасность', en: 'Security' },
  'health.changed': { ru: 'Здоровье', en: 'Health' },
  'backup.status': { ru: 'Бэкап', en: 'Backup' },
};

function describeEvent(entry){
  var lang = currentLang();
  var payload = entry.payload || {};
  if(entry.topic === 'security.alert' && payload.reason === 'account_locked'){
    return (lang === 'ru'
      ? 'Учётная запись заблокирована после неудачных попыток входа: '
      : 'Account locked after failed sign-in attempts: ') + (payload.username || '');
  }
  if(entry.topic === 'health.changed'){
    return (lang === 'ru' ? 'Изменение здоровья: ' : 'Health change: ')
      + (payload.component || '') + ' ' + (payload.previous_status || '') + ' → ' + (payload.status || '');
  }
  var prefix = lang === 'ru' ? 'Событие: ' : 'Event: ';
  return prefix + entry.topic + ' ' + JSON.stringify(payload);
}

function renderEventLog(){
  var box = document.getElementById('eventLogList');
  if(!box) return;
  var events = (lastOverview && lastOverview.event_log) || [];
  box.innerHTML = '';
  if(events.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = currentLang() === 'ru' ? 'Событий пока нет' : 'No events yet';
    box.appendChild(empty);
    return;
  }
  events.forEach(function(entry){
    var row = document.createElement('div');
    row.className = 'logrow';
    var ft = document.createElement('span');
    ft.className = 'ft';
    ft.textContent = formatTimestamp(entry.created_at);
    var lvl = document.createElement('span');
    lvl.className = 'lvl ' + (entry.topic === 'security.alert' ? 'warn' : 'info');
    lvl.textContent = (EVENT_TOPIC_LABELS[entry.topic] || { ru: entry.topic, en: entry.topic })[currentLang()];
    var msg = document.createElement('span');
    msg.textContent = describeEvent(entry);
    row.appendChild(ft);
    row.appendChild(lvl);
    row.appendChild(msg);
    box.appendChild(row);
  });
}

/* ---------- консоль (мастер-деталь) ---------- */
var lastConsoleId = null;
var lastConsoleData = null;

async function openConsole(id){
  lastConsoleId = id;
  lastConsoleData = null;
  show('view-console');
  var errBox = document.getElementById('conError');
  errBox.hidden = true;
  // Cleared here (once, when a console is freshly opened) rather than in
  // renderConsole() itself: refreshBackupConsole() also calls
  // renderConsole() right after a snapshot/restore action completes, and
  // that call must NOT wipe the status message the action just set.
  setConActionStatus(null);
  try{
    var res = await apiFetch(CONSOLE_ROUTES[id]);
    if(!res.ok){
      var body = await res.json().catch(function(){ return {}; });
      var code = (body.detail && body.detail.error) || 'unknown_error';
      errBox.textContent = translateError(code);
      errBox.hidden = false;
      return;
    }
    lastConsoleData = await res.json();
    renderConsole();
  } catch(e){
    errBox.textContent = translateError('network_error');
    errBox.hidden = false;
  }
}

function closeConsole(){
  lastConsoleId = null;
  lastConsoleData = null;
  show('view-overview');
  loadOverview(); // pick up any toggle made while inside the console
}

function renderConsole(){
  if(!lastConsoleId || !lastConsoleData) return;
  var meta = CONSOLE_META[lastConsoleId];
  var lang = currentLang();

  document.getElementById('conIcon').textContent = meta.icon;
  document.getElementById('conTitle').textContent = meta.title[lang];
  document.getElementById('conEngine').textContent = (lastConsoleData.engine || [])
    .map(function(code){ return TOOL_LABELS[code] || code; })
    .join(' · ');

  // A-11: consoles with a single real connector (`ids`/`network`/`logs`)
  // report `connector.status` directly. A-15/A-17/A-18 added a SECOND
  // shape for consoles with more than one independent source
  // (`perimeter`'s os_firewall+disk_encryption+crowdsec_bouncer, `av`'s
  // osquery+clamav) — a `connectors` dict keyed by source id, deliberately
  // NOT read anywhere in this file until this fix (2026-07-16 finding: the
  // backend had real, working connector data — e.g. a real CrowdSec bouncer
  // connected on `perimeter` — that this UI never displayed at all, because
  // `lastConsoleData.connector` is `null` for those two consoles and the
  // old check below only ever looked at that singular field. A user opening
  // "Защита периметра" saw no error banner AND no confirmation either —
  // just silence, indistinguishable from a console with no connector
  // concept at all like `backup`). Both shapes now render into the same
  // banner; openConsole() already resets `conError` on every open.
  var connErrBox = document.getElementById('conError');
  var connectorLines = [];
  if(lastConsoleData.connector && lastConsoleData.connector.status !== 'ok'){
    connectorLines.push(translateError('connector_' + lastConsoleData.connector.status));
  }
  if(lastConsoleData.connectors){
    Object.keys(lastConsoleData.connectors).forEach(function(key){
      var c = lastConsoleData.connectors[key];
      if(c && c.status && c.status !== 'ok'){
        var label = TOOL_LABELS[key] || key;
        connectorLines.push(label + ': ' + translateError('connector_' + c.status));
      }
    });
  }
  if(connectorLines.length){
    connErrBox.textContent = connectorLines.join(' · ');
    connErrBox.hidden = false;
  } else {
    connErrBox.hidden = true;
  }

  var powerBtn = document.getElementById('conPower');
  var enabled = !!lastConsoleData.enabled;
  powerBtn.classList.toggle('off', !enabled);
  powerBtn.disabled = false;
  powerBtn.textContent = enabled ? (lang === 'ru' ? 'Включено' : 'Enabled') : (lang === 'ru' ? 'Выключено' : 'Disabled');

  var metricsBox = document.getElementById('conMetrics');
  metricsBox.innerHTML = '';
  var metrics = lastConsoleData.metrics || {};
  Object.keys(meta.metricLabels).forEach(function(key){
    var tile = document.createElement('div');
    tile.className = 'kbstat';
    var n = document.createElement('span');
    n.className = 'kbstat-n';
    n.textContent = key.indexOf('_at') !== -1 ? formatTimestamp(metrics[key]) : formatValue(metrics[key]);
    var l = document.createElement('div');
    l.className = 'kbstat-l';
    l.textContent = meta.metricLabels[key][lang];
    tile.appendChild(n);
    tile.appendChild(l);
    metricsBox.appendChild(tile);
  });

  // Chart: the field shape (chart.values / chart.inbound+outbound) is real
  // and already returned by the backend, but Phase 0 has no real numbers
  // behind it yet (A-11) — an all-zero canvas would look like a rendering
  // bug more than an honest "nothing to show yet". A labelled empty-state
  // is the simpler, more honest choice for this phase; see task report.
  document.getElementById('conChartCard').hidden = false;
  document.getElementById('conChartTitle').textContent = meta.chartTitle[lang];

  var listSection = document.getElementById('conListSection');
  if(meta.listKey){
    listSection.hidden = false;
    document.getElementById('conListTitle').textContent = meta.listTitle[lang];
    renderConsoleList(lastConsoleData[meta.listKey] || []);
  } else {
    listSection.hidden = true;
  }

  var actionsBox = document.getElementById('conActions');
  actionsBox.innerHTML = '';
  meta.actions.forEach(function(action){
    var btn = document.createElement('button');
    btn.className = 'btn-ghost';
    btn.type = 'button';
    btn.textContent = action[lang];
    // A-12: the backup console is the first one with a real tool behind
    // some of its actions (ACTION_HANDLERS below) — those get enabled with
    // a real onclick; every other action on every other console still has
    // no real tool yet (A-11), so it stays a disabled placeholder exactly
    // as before.
    var handler = action.id && ACTION_HANDLERS[action.id];
    if(handler){
      btn.disabled = false;
      btn.onclick = function(){ handler(btn); };
    } else {
      btn.disabled = true;
      if(action.soon){
        btn.title = lang === 'ru' ? action.tipRu : action.tipEn;
      } else {
        btn.title = lang === 'ru'
          ? 'Доступно после интеграции инструментов безопасности (A-11)'
          : 'Available once the security tools are integrated (A-11)';
      }
    }
    actionsBox.appendChild(btn);
  });

  var settingsBox = document.getElementById('conSettings');
  settingsBox.innerHTML = '';
  var settings = lastConsoleData.settings || {};
  Object.keys(meta.settingLabels).forEach(function(key){
    var row = document.createElement('div');
    row.className = 'st-row';
    var label = document.createElement('b');
    label.textContent = meta.settingLabels[key][lang];
    row.appendChild(label);

    var value = settings[key];
    if(typeof value === 'boolean'){
      var tgl = document.createElement('span');
      tgl.className = 'st-tgl' + (value ? ' on' : '');
      tgl.textContent = value ? (lang === 'ru' ? 'включено' : 'on') : (lang === 'ru' ? 'выключено' : 'off');
      row.appendChild(tgl);
    } else {
      var val = document.createElement('span');
      val.className = 'st-val';
      val.textContent = formatValue(value).replace(/_/g, ' ');
      row.appendChild(val);
    }
    settingsBox.appendChild(row);
  });
}

function renderConsoleList(items){
  var box = document.getElementById('conList');
  box.innerHTML = '';
  if(!items || items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = currentLang() === 'ru' ? 'Нет данных' : 'No data yet';
    box.appendChild(empty);
    return;
  }
  var lang = currentLang();
  if(lastConsoleId === 'backup'){
    items.forEach(function(item){
      var row = document.createElement('div');
      row.className = 'con-row';
      var name = document.createElement('span');
      name.className = 'cr-k';
      var label = MODULE_LABELS[item.id] || { ru: item.id, en: item.id };
      name.textContent = label[lang];
      var last = document.createElement('span');
      last.style.marginLeft = 'auto';
      last.style.color = 'var(--muted)';
      last.textContent = formatTimestamp(item.last_backup_at);
      var auto = document.createElement('span');
      auto.className = 'st-tgl' + (item.auto ? ' on' : '');
      auto.textContent = item.auto ? (lang === 'ru' ? 'авто' : 'auto') : (lang === 'ru' ? 'вручную' : 'manual');
      row.appendChild(name);
      row.appendChild(last);
      row.appendChild(auto);
      box.appendChild(row);
    });
    return;
  }
  // Generic fallback for the other consoles' lists (recent_attempts /
  // connections / entries) — all empty by default in Phase 0 (A-11 fills
  // them in), so a generic key:value rendering is enough for now; it will
  // render sensibly once those arrays carry real rows.
  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'con-row';
    Object.keys(item).forEach(function(key){
      var span = document.createElement('span');
      var k = document.createElement('span');
      k.className = 'cr-k';
      k.textContent = key + ': ';
      span.appendChild(k);
      span.appendChild(document.createTextNode(String(item[key])));
      row.appendChild(span);
    });
    box.appendChild(row);
  });
}

async function handleTogglePower(){
  if(!lastConsoleId) return;
  var nextEnabled = lastConsoleData ? !lastConsoleData.enabled : true;
  var powerBtn = document.getElementById('conPower');
  powerBtn.disabled = true;
  try{
    var res = await apiFetch('/security/consoles/' + lastConsoleId + '/toggle', {
      method: 'POST',
      body: JSON.stringify({ enabled: nextEnabled }),
    });
    if(!res.ok){
      powerBtn.disabled = false;
      return;
    }
    var body = await res.json();
    if(lastConsoleData){
      lastConsoleData.enabled = body.enabled;
      lastConsoleData.status = body.status;
    }
    renderConsole();
    // Refresh the overview snapshot right away (not just on `closeConsole()`)
    // so the topbar's security shield pill — fed by `lastOverview.status`,
    // the worst-of-all-6-consoles aggregate — updates immediately, even
    // while the user is still looking at this console's detail view.
    loadOverview();
  } catch(e){
    powerBtn.disabled = false;
  }
}

/* ---------- A-12: реальные действия консоли «Резервные копии» ----------
   Единственная консоль Фазы 0 с реальным инструментом за кнопками
   «Управление» (restic) — см. renderConsole()'s ACTION_HANDLERS lookup
   выше. Остальные консоли/кнопки остаются задизейбленными (A-11 ещё нет). */
var ACTION_HANDLERS = {
  create_snapshot: handleCreateSnapshot,
  restore_system: handleRestoreSystem,
};

function setConActionStatus(text, kind){
  var box = document.getElementById('conActionStatus');
  if(!box) return;
  if(!text){
    box.hidden = true;
    box.textContent = '';
    return;
  }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

function describeBackupJob(job){
  var lang = currentLang();
  if(job.status === 'success'){
    return lang === 'ru'
      ? 'Готово: ' + formatValue(job.size_bytes) + ' байт, ' + formatTimestamp(job.finished_at)
      : 'Done: ' + formatValue(job.size_bytes) + ' bytes, ' + formatTimestamp(job.finished_at);
  }
  return lang === 'ru'
    ? 'Операция резервного копирования не удалась.'
    : 'The backup operation failed.';
}

async function refreshBackupConsole(){
  if(lastConsoleId !== 'backup') return;
  try{
    var res = await apiFetch(CONSOLE_ROUTES.backup);
    if(!res.ok) return;
    lastConsoleData = await res.json();
    renderConsole(); // rebuilds #conActions too — does not touch #conActionStatus
  } catch(e){ /* network hiccup — keep showing the last known console data */ }
}

async function handleCreateSnapshot(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/backup/snapshot', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    setConActionStatus(describeBackupJob(body), body.status === 'success' ? 'success' : 'error');
    await refreshBackupConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleRestoreSystem(btn){
  var lang = currentLang();
  var confirmed = window.confirm(lang === 'ru'
    ? 'Восстановить систему из последней резервной копии? Текущие данные будут заменены.'
    : 'Restore the system from the latest backup? Current data will be overwritten.');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/backup/restore/latest', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    setConActionStatus(describeBackupJob(body), body.status === 'success' ? 'success' : 'error');
    await refreshBackupConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-13: уведомления и каналы ----------
   Channel 4 (иконки/индикаторы панели) honestly implemented via poll, not
   push: the panel has no WebSocket/SSE in Phase 0 (see task report), so the
   badge/list below only ever reflect the LAST poll response — a genuinely
   new server-side event becomes visible here on the next tick
   (NOTIF_POLL_INTERVAL_MS), same as every other pill on this page
   (#healthPill/#securityShieldPill), just on its own timer since neither of
   those already polls on an interval either. */
var NOTIF_POLL_INTERVAL_MS = 8000;
var notifPollTimer = null;
var lastNotifications = null;   // last GET /notifications/recent response
var lastNotifSettings = null;   // last GET /notifications/settings response

function startNotificationsPolling(){
  stopNotificationsPolling();
  notifPollTimer = setInterval(loadNotificationsPill, NOTIF_POLL_INTERVAL_MS);
}
function stopNotificationsPolling(){
  if(notifPollTimer){ clearInterval(notifPollTimer); notifPollTimer = null; }
}

async function loadNotificationsPill(){
  try{
    var res = await apiFetch('/notifications/recent?limit=10');
    if(!res.ok) return;
    lastNotifications = await res.json();
    renderNotificationsPill();
    // If the notifications screen happens to be open, this same poll tick
    // keeps its list current too — no second timer needed.
    var view = document.getElementById('view-notifications');
    if(view && view.classList.contains('active')) renderNotificationsList();
  } catch(e){ /* network hiccup — badge just keeps its last known count */ }
}

function renderNotificationsPill(){
  var pill = document.getElementById('notificationsPill');
  var text = document.getElementById('notificationsPillText');
  if(!pill || !lastNotifications) return;
  var count = lastNotifications.unread_count || 0;
  var criticalCount = lastNotifications.unread_critical_count || 0;
  pill.classList.remove('ok', 'degraded', 'down');
  pill.classList.add(count === 0 ? 'ok' : (criticalCount > 0 ? 'down' : 'degraded'));
  text.innerHTML = '🔔' + (count > 0 ? ' <span class="badge-count">' + count + '</span>' : '');
}

async function openNotifications(){
  show('view-notifications');
  await Promise.all([loadNotificationsFull(), loadNotificationsSettings()]);
}
function closeNotifications(){
  show('view-overview');
  loadOverview();
}

async function loadNotificationsFull(){
  try{
    var res = await apiFetch('/notifications/recent?limit=50');
    if(!res.ok) return;
    lastNotifications = await res.json();
    renderNotificationsPill();
    renderNotificationsList();
  } catch(e){ /* network hiccup — list just keeps showing the last snapshot */ }
}

async function loadNotificationsSettings(){
  try{
    var res = await apiFetch('/notifications/settings');
    if(!res.ok) return;
    lastNotifSettings = await res.json();
    renderNotificationsSettings();
  } catch(e){ /* network hiccup — settings section just keeps its last snapshot */ }
}

function renderNotificationsList(){
  var box = document.getElementById('notifList');
  if(!box) return;
  box.innerHTML = '';
  var items = (lastNotifications && lastNotifications.items) || [];
  var lang = currentLang();
  if(items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Уведомлений пока нет' : 'No notifications yet';
    box.appendChild(empty);
    return;
  }
  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'notif-item' + (!item.read_at ? ' unread' : '');

    var topic = document.createElement('span');
    topic.className = 'ni-topic';
    topic.textContent = (EVENT_TOPIC_LABELS[item.topic] || { ru: item.topic, en: item.topic })[lang];

    var ft = document.createElement('span');
    ft.className = 'ft';
    ft.textContent = formatTimestamp(item.created_at);

    var msg = document.createElement('span');
    msg.className = 'ni-msg';
    msg.textContent = describeEvent(item);

    row.appendChild(topic);
    row.appendChild(ft);
    row.appendChild(msg);

    if(item.critical && !item.acknowledged_at){
      var ackBtn = document.createElement('button');
      ackBtn.className = 'btn-ghost ni-ack';
      ackBtn.type = 'button';
      ackBtn.textContent = lang === 'ru' ? 'Подтвердить' : 'Acknowledge';
      ackBtn.onclick = function(){ handleAckNotification(item.id, ackBtn); };
      row.appendChild(ackBtn);
    } else if(item.acknowledged_at){
      var ackTag = document.createElement('span');
      ackTag.className = 'st-tgl on ni-ack';
      ackTag.textContent = lang === 'ru' ? 'подтверждено' : 'acknowledged';
      row.appendChild(ackTag);
    }
    box.appendChild(row);
  });
}

async function handleMarkAllRead(){
  try{
    var res = await apiFetch('/notifications/mark-read', { method: 'POST' });
    if(res.ok) await loadNotificationsFull();
  } catch(e){ /* network hiccup — badge stays as-is, next poll retries */ }
}

async function handleAckNotification(id, btn){
  if(btn) btn.disabled = true;
  try{
    var res = await apiFetch('/notifications/' + id + '/ack', { method: 'POST' });
    if(res.ok) await loadNotificationsFull();
  } catch(e){
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- матрица «функция x канал» + тихие часы/эскалация/доверенные лица ----------
   Каналы 1-3 (звук/голос/текстовое окно): чекбоксы реальны и сохраняются
   (намерение пользователя записывается в матрицу), но их реальная доставка
   НЕ подключена в Фазе 0 — see channels.CHANNEL_DELIVERY_IMPLEMENTED; UI
   honestly labels them "(не доставляется)"/"(not delivered)" using the
   server's own channel_availability flags, not a hardcoded guess.
   Канал 6 (СМС/звонок) — чекбокс задизейблен: редактировать намерение для
   канала, который не существует (нужен телефон-терминал, бэклог §9.1),
   было бы обманчивым, не просто "пока не доставляется". */
var CHANNEL_ORDER = ['sound', 'voice', 'text_window', 'panel_icon', 'email', 'sms_call'];
var CHANNEL_LABELS = {
  sound: { ru: 'Звук', en: 'Sound' },
  voice: { ru: 'Голос', en: 'Voice' },
  text_window: { ru: 'Текстовое окно', en: 'Text window' },
  panel_icon: { ru: 'Иконка панели', en: 'Panel icon' },
  email: { ru: 'Почта', en: 'Email' },
  sms_call: { ru: 'СМС/звонок', en: 'SMS/call' },
};

function renderNotificationsSettings(){
  if(!lastNotifSettings) return;
  renderNotifMatrix();
  renderNotifQuietHoursAndEscalation();
  renderTrustedContactsInput();
}

function renderNotifMatrix(){
  var box = document.getElementById('notifMatrix');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();
  var matrix = lastNotifSettings.matrix || {};
  var availability = lastNotifSettings.channel_availability || {};

  Object.keys(matrix).forEach(function(topic){
    var entry = matrix[topic];
    var row = document.createElement('div');
    row.className = 'notif-matrix-row';

    var label = document.createElement('span');
    label.className = 'cr-k';
    var topicLabel = (EVENT_TOPIC_LABELS[topic] || { ru: topic, en: topic })[lang];
    label.textContent = topicLabel + (entry.critical ? (lang === 'ru' ? ' · критично' : ' · critical') : '');
    row.appendChild(label);

    var chans = document.createElement('div');
    chans.className = 'notif-chans';
    CHANNEL_ORDER.forEach(function(channel){
      var implemented = !!availability[channel];
      var wrap = document.createElement('label');
      wrap.className = 'notif-chan-tgl' + (implemented ? '' : ' unavailable');

      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = entry.channels.indexOf(channel) !== -1;
      cb.dataset.channel = channel;
      // Channel 6 (sms_call): disabled outright — see module docstring above.
      cb.disabled = (channel === 'sms_call');
      cb.onchange = function(){ handleMatrixChange(topic, chans); };

      var txt = document.createElement('span');
      var suffix = implemented ? '' : (lang === 'ru' ? ' (не доставляется)' : ' (not delivered)');
      txt.textContent = CHANNEL_LABELS[channel][lang] + suffix;

      wrap.appendChild(cb);
      wrap.appendChild(txt);
      chans.appendChild(wrap);
    });
    row.appendChild(chans);
    box.appendChild(row);
  });
}

async function handleMatrixChange(topic, container){
  var checked = Array.prototype.slice.call(container.querySelectorAll('input[type=checkbox]'))
    .filter(function(cb){ return cb.checked; })
    .map(function(cb){ return cb.dataset.channel; });
  try{
    var res = await apiFetch('/notifications/settings/matrix/' + encodeURIComponent(topic), {
      method: 'POST',
      body: JSON.stringify({ channels: checked }),
    });
    if(res.ok){
      var body = await res.json();
      if(lastNotifSettings && lastNotifSettings.matrix[topic]){
        lastNotifSettings.matrix[topic].channels = body.channels;
      }
    }
  } catch(e){ /* network hiccup — reopening the screen reloads the real state */ }
}

function stRow(labelText, valueText, valueClass){
  var row = document.createElement('div');
  row.className = 'st-row';
  var label = document.createElement('b');
  label.textContent = labelText;
  var val = document.createElement('span');
  val.className = valueClass || 'st-val';
  val.textContent = valueText;
  row.appendChild(label);
  row.appendChild(val);
  return row;
}

function renderNotifQuietHoursAndEscalation(){
  var lang = currentLang();
  var qh = lastNotifSettings.quiet_hours || {};
  var esc = lastNotifSettings.escalation || {};

  // Read-only in Phase 0 (see task report: quiet hours/escalation timing
  // come from Settings/.env, not yet a runtime-editable store — only the
  // matrix and trusted contacts are genuinely editable here).
  var qhBox = document.getElementById('notifQuietHours');
  if(qhBox){
    qhBox.innerHTML = '';
    qhBox.appendChild(stRow(
      lang === 'ru' ? 'Тихие часы' : 'Quiet hours',
      qh.enabled ? (lang === 'ru' ? 'включены' : 'enabled') : (lang === 'ru' ? 'выключены' : 'disabled'),
      'st-tgl' + (qh.enabled ? ' on' : '')
    ));
    qhBox.appendChild(stRow(lang === 'ru' ? 'Интервал' : 'Window', (qh.start || '—') + ' – ' + (qh.end || '—')));
  }

  var escBox = document.getElementById('notifEscalation');
  if(escBox){
    escBox.innerHTML = '';
    escBox.appendChild(stRow(
      lang === 'ru' ? 'Эскалация после (мин)' : 'Escalate after (min)',
      formatValue(esc.minutes)
    ));
    escBox.appendChild(stRow(
      lang === 'ru' ? 'Проверка раз в (сек)' : 'Check interval (sec)',
      formatValue(esc.check_interval_seconds)
    ));
    escBox.appendChild(stRow(
      lang === 'ru' ? 'Канал 6 (СМС/звонок)' : 'Channel 6 (SMS/call)',
      lang === 'ru' ? 'не реализован — нужен телефон-терминал' : 'not implemented — needs a phone-terminal'
    ));
  }
}

function renderTrustedContactsInput(){
  var input = document.getElementById('trustedContactsInput');
  if(!input) return;
  var contacts = lastNotifSettings.trusted_contacts || [];
  // Only replace the field's value if the user isn't mid-edit (has focus) —
  // avoids clobbering an in-progress edit if a poll tick re-renders settings.
  if(document.activeElement !== input) input.value = contacts.join(', ');
}

async function handleSaveTrustedContacts(){
  var input = document.getElementById('trustedContactsInput');
  var emails = input.value.split(',').map(function(e){ return e.trim(); }).filter(Boolean);
  try{
    var res = await apiFetch('/notifications/settings/trusted-contacts', {
      method: 'POST',
      body: JSON.stringify({ emails: emails }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setNotifContactsStatus(translateError(code), 'error');
      return;
    }
    if(lastNotifSettings) lastNotifSettings.trusted_contacts = body.trusted_contacts;
    setNotifContactsStatus(
      currentLang() === 'ru' ? 'Сохранено.' : 'Saved.', 'success'
    );
  } catch(e){
    setNotifContactsStatus(translateError('network_error'), 'error');
  }
}

function setNotifContactsStatus(text, kind){
  var box = document.getElementById('notifContactsStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

/* ---------- инициализация ---------- */
document.addEventListener('DOMContentLoaded', function(){
  applyLang(currentLang());

  var token = localStorage.getItem(TOKEN_KEY);
  if(!token){
    showLogin();
    return;
  }
  apiFetch('/auth/me').then(function(res){
    if(res.ok){ showPanel(); } else { showLogin(); }
  }).catch(function(){ showLogin(); });
});
