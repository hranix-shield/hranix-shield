/* Hranix Shield — веб-панель безопасности (A-10).
   Auth (минимальный экран входа) + локализация RU/EN (data-ru/data-en,
   тот же паттерн applyLang, что в site/prototype/assets/site.js) + обзор
   и 6 консолей «Защиты» на реальных эндпоинтах /security/*. */

var TOKEN_KEY = 'hranix_shield_token';
var LANG_KEY = 'hranix-lang';

/* ---------- локализация ---------- */
function currentLang(){ return localStorage.getItem(LANG_KEY) || 'ru'; }

function applyLang(l){
  // A-58: diagnostic hook for the floating language-reset finding (F4) —
  // a `hranix-lang` console.debug line readable by the live browser run;
  // cheap, no behaviour change, kept deliberately as the diagnostic trail.
  var activeView = document.querySelector('.view.active');
  console.debug('hranix-lang', 'applyLang', l,
    'view=' + (activeView ? activeView.id : 'none'),
    'console=' + (lastConsoleId || 'none'));
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
  // A-37: the port-detail modal builds its own row content in JS (not
  // data-ru/data-en static markup) — same "re-render already-fetched data
  // in the new language" reasoning as every other lastXxx re-render above.
  if(portModalItem) renderPortModal();
  // A-43: same reasoning — the scenario-thresholds modal also builds its
  // rows in JS, and stays open across a language toggle (unlike the port
  // modal, this one is only ever populated after a successful elevated
  // read, so `scenarioThresholds` — not a "is the overlay open" flag — is
  // the right re-render guard, mirroring `portModalItem`'s own null-checked
  // guard above).
  if(scenarioThresholds) renderScenarioThresholdsModal();
  // A-57: the action-status boxes carry text set at action time, not by a
  // render pass — re-apply the remembered {ru,en} pairs so an already-shown
  // result switches language too (находка F3), same "re-render without a
  // refetch" discipline as every lastXxx re-render above.
  reapplyConActionStatusLang();
  // A-60: экран «Настройки → Стек защиты» строит статус-строки и пошаговый
  // результат в JS (не data-ru разметкой) — тот же re-render без refetch.
  if(lastStackStatus) renderStackStatus();
  if(lastStackSteps) renderStackSteps();
}
function toggleLang(){
  applyLang(currentLang() === 'ru' ? 'en' : 'ru');
}

/* ---------- тема (A-48) ---------- */
var THEME_KEY = 'hranix-theme';
function currentTheme(){
  var t = localStorage.getItem(THEME_KEY);
  if(t) return t;
  return (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
}
function applyTheme(t){
  document.documentElement.classList.toggle('dark', t === 'dark');
  localStorage.setItem(THEME_KEY, t);
  var icon = t === 'dark' ? '☀️' : '🌙';
  var themeBtn = document.getElementById('themeBtn');
  if(themeBtn) themeBtn.textContent = icon;
  var themeBtnLogin = document.getElementById('themeTglLogin');
  if(themeBtnLogin) themeBtnLogin.textContent = icon;
  // The three canvas charts (drawBarChart/drawGroupedBarChart/
  // drawConnectionsMap) already read their colours via getComputedStyle on
  // every draw, but a canvas is a static bitmap — it does not repaint
  // itself just because a CSS variable changed. renderConsole() is the
  // same "re-render already-fetched data without a refetch" path
  // applyLang() above already uses for this exact reason.
  if(lastConsoleId && lastConsoleData) renderConsole();
}
function toggleTheme(){
  applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
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
  // A-41-fix: this console's passive on-load check (fetch_firewall_rules,
  // never prompts) honestly reports permission_denied here on macOS
  // (`pfctl -s rules` needs root) — but the generic message above predates
  // A-36's elevated_run() and reads as "there is nothing you can do from
  // here", when there in fact already IS an in-app one-shot elevated path
  // for this exact data: the «Правила фаервола» button in «Управление»
  // below (POST .../firewall/rules, os_firewall.read_firewall_rules).
  // A real user found this confusing — this is the same permission_denied
  // status, just a connector-specific, actionable wording pointing at the
  // button that already solves it, instead of the generic one that reads
  // as a dead end (see `renderConsole`'s connectorLines loop for the
  // `key === 'firewall_rules'` special case that selects this string).
  connector_permission_denied_firewall_rules: {
    ru: 'Недостаточно прав для проверки без запроса — нажмите «Правила фаервола» в разделе '
      + '«Управление» ниже, чтобы посмотреть их через разовый системный запрос прав (без '
      + 'сохранения повышенных прав для всего приложения).',
    en: 'Insufficient permissions to check without a prompt — click "Firewall rules" in '
      + 'Management below to view them via a one-time OS elevation prompt (no wholesale '
      + 'privilege elevation for the whole app).',
  },
  // A-38: `network_profile`'s own connector.status — a network genuinely
  // not detected right now (Wi-Fi off, no cable plugged in) is an honest,
  // ordinary state, not a tool failure, so it gets its own wording rather
  // than reusing connector_unreachable's "check the service is running"
  // phrasing (there is no "service" here to check).
  connector_not_connected: {
    ru: 'Сеть не определена — нет активного сетевого подключения.',
    en: 'No network detected — no active network connection.',
  },
  // A-38: `POST .../network-profile/category`'s own error — assigning a
  // category needs a currently-detected network to attach it to.
  network_not_detected: {
    ru: 'Не удалось определить текущую сеть прямо сейчас — попробуйте ещё раз.',
    en: 'Could not detect the current network right now — try again.',
  },
  // A-27: `/consoles/av/clamav/*` action-endpoint codes (quick/full scan,
  // reload, quarantine list/restore) — distinct from the generic
  // `connector_*` codes above because these describe a specific ACTION's
  // outcome, not a console's overall connector status.
  clamav_not_configured: {
    ru: 'ClamAV не подключён — задайте параметры подключения в .env (CLAMAV_ENABLED).',
    en: 'ClamAV is not connected — configure connection settings in .env (CLAMAV_ENABLED).',
  },
  clamav_unreachable: {
    ru: 'ClamAV недоступен — проверьте, что контейнер clamd запущен.',
    en: 'ClamAV is unavailable — check that the clamd container is running.',
  },
  path_outside_scan_roots: {
    ru: 'Этот путь вне разрешённых для сканирования директорий.',
    en: 'This path is outside the directories allowed for scanning.',
  },
  file_not_found: {
    ru: 'Файл не найден.',
    en: 'File not found.',
  },
  // A-33: `/consoles/av/clamav/scan/custom`'s own "path exists but was not
  // found on disk" code — distinct from `file_not_found` above (that one is
  // quarantine's "this exact file is gone"), since a custom-scan target is
  // usually a folder, not necessarily a single file.
  scan_path_not_found: {
    ru: 'Указанный путь не найден.',
    en: 'The specified path was not found.',
  },
  scan_job_not_found: {
    ru: 'Задача проверки не найдена.',
    en: 'Scan job not found.',
  },
  quarantine_item_not_found: {
    ru: 'Запись карантина не найдена — возможно, уже восстановлена.',
    en: 'Quarantine item not found — it may already have been restored.',
  },
  restore_path_conflict: {
    ru: 'Исходный путь уже занят другим файлом — восстановление отменено, файл остался в карантине.',
    en: 'The original path is already occupied by another file — restore cancelled, the file stays in quarantine.',
  },
  // A-30: `POST /consoles/logs/wazuh/syscheck`'s own error codes — same
  // "not_configured vs unreachable vs unauthorized" vocabulary as
  // connector_* above, just prefixed so this specific action's errors read
  // distinctly from the passive `logs` console load itself failing.
  wazuh_not_configured: {
    ru: 'Wazuh не подключён — задайте параметры подключения в .env.',
    en: 'Wazuh is not connected — configure connection settings in .env.',
  },
  wazuh_unreachable: {
    ru: 'Wazuh Manager недоступен — проверьте, что контейнер запущен.',
    en: 'Wazuh Manager is unreachable — check that the container is running.',
  },
  wazuh_unauthorized: {
    ru: 'Wazuh Manager отклонил ключ доступа — проверьте настройки.',
    en: 'Wazuh Manager rejected the access key — check configuration.',
  },
  // A-29: errors from the two new CrowdSec write endpoints
  // (/security/consoles/ids/crowdsec/{ban,decisions/{id}}) — a distinct
  // `crowdsec_*` namespace from the generic `connector_*` codes above,
  // since these describe an ACTION's outcome, not a console's overall
  // connector status banner.
  crowdsec_write_not_configured: {
    ru: 'Бан/разбан не настроены — требуется отдельный machine-уровня LAPI-логин CrowdSec (см. документацию по настройке).',
    en: 'Ban/unban not configured — requires a separate CrowdSec machine-level LAPI login (see setup documentation).',
  },
  crowdsec_unreachable: {
    ru: 'CrowdSec недоступен — проверьте, что контейнер запущен.',
    en: 'CrowdSec is unavailable — check that the container is running.',
  },
  crowdsec_unauthorized: {
    ru: 'CrowdSec отклонил учётные данные — проверьте настройки machine-логина.',
    en: 'CrowdSec rejected the credentials — check the machine-login configuration.',
  },
  crowdsec_invalid_ip: {
    ru: 'Некорректный IP-адрес.',
    en: 'Invalid IP address.',
  },
  crowdsec_rejected: {
    ru: 'CrowdSec принял запрос, но не создал решение — проверьте IP-адрес.',
    en: 'CrowdSec accepted the request but created no decision — check the IP address.',
  },
  crowdsec_decision_not_found: {
    ru: 'Решение уже снято или не найдено.',
    en: 'Decision already removed or not found.',
  },
  // A-36: `/consoles/perimeter/firewall/*`'s own error codes — a real,
  // one-time OS admin-password prompt was attempted server-side.
  // `elevation_cancelled` is deliberately worded as a neutral, non-scary
  // fact (the user declined the prompt — nothing broke), never phrased
  // like `elevation_failed` (a real problem with the elevated command
  // itself) — see app.js's handleFirewallRules/handleBlockAllIncoming for
  // the matching neutral 'warn' status-box styling.
  elevation_cancelled: {
    ru: 'Запрос пароля администратора отменён — действие не выполнено.',
    en: 'The administrator-password prompt was cancelled — no action was taken.',
  },
  elevation_failed: {
    ru: 'Не удалось выполнить действие с повышенными правами — см. логи сервера.',
    en: 'The elevated-privilege action failed — see server logs for details.',
  },
  // A-52: `/consoles/network/ips/{ip}/block` and
  // `/consoles/network/processes/{pid}/terminate`'s own error codes.
  // `elevation_cancelled`/`elevation_failed` above are reused as-is (same
  // elevated_run() mechanism). `invalid_ip` is a plain client-input problem
  // (ipaddress.ip_address rejected the string), NOT elevation-related —
  // same class as `crowdsec_invalid_ip` above but a distinct code since the
  // two features are unrelated. `process_identity_mismatch` is the honest
  // "well-formed request, but the assumed state has moved on" outcome of
  // os_processes.py's own PID-reuse race check — deliberately NOT worded as
  // an error/failure (nothing went wrong; the process the operator meant to
  // terminate had already exited, and a NEW unrelated process now happens
  // to hold that PID).
  invalid_ip: {
    ru: 'Некорректный IP-адрес.',
    en: 'Invalid IP address.',
  },
  invalid_pid: {
    ru: 'Некорректный PID процесса.',
    en: 'Invalid process PID.',
  },
  process_identity_mismatch: {
    ru: 'Процесс с этим PID уже завершился, и его номер занял другой процесс — действие отменено для безопасности. Обновите список соединений и попробуйте снова.',
    en: 'The process with this PID has already exited and a different process now holds that PID — the action was cancelled for safety. Refresh the connections list and try again.',
  },
  // Post-merge user request (2026-08-02): `/consoles/av/clamav/pick-folder`'s
  // own error codes — deliberately NOT reusing `elevation_cancelled` above
  // (see clamav.py's ClamAvFolderPickError docstring: this dialog never
  // asks for OS admin privileges, so that wording would be false here).
  folder_pick_cancelled: {
    ru: 'Выбор папки отменён.',
    en: 'Folder selection was cancelled.',
  },
  unsupported_platform: {
    ru: 'Нативный выбор папки пока доступен только на macOS — введите путь вручную.',
    en: 'The native folder picker is only available on macOS for now — type the path manually.',
  },
  // A-43: `/consoles/ids/crowdsec/scenario-thresholds*`'s own error codes —
  // `elevation_cancelled`/`elevation_failed` above are reused as-is (same
  // elevated_run() mechanism), these five are specific to this action.
  scenario_not_found: {
    ru: 'Сценарий не найден — возможно, он был удалён или переименован.',
    en: 'Scenario not found — it may have been removed or renamed.',
  },
  scenario_has_no_threshold: {
    ru: 'У этого сценария нет понятия порога.',
    en: 'This scenario has no concept of a threshold.',
  },
  invalid_capacity: {
    ru: 'Capacity должен быть положительным целым числом или -1.',
    en: 'Capacity must be a positive integer or -1.',
  },
  invalid_leakspeed: {
    ru: 'Leakspeed должен быть числом с единицей измерения (например 10s, 2h).',
    en: 'Leakspeed must be a number with a unit (e.g. 10s, 2h).',
  },
  readback_mismatch: {
    ru: 'Контейнер перезапущен без ошибки, но повторное чтение показывает старое значение — попробуйте ещё раз.',
    en: 'The container restarted without error, but a fresh read still shows the old value — try again.',
  },
  // A-44: `/consoles/ids/crowdsec/allowlist*`'s own error codes —
  // `elevation_cancelled`/`elevation_failed` above are reused as-is (same
  // elevated_run() mechanism as A-43), these four are specific to this
  // action. Deliberately NOT sharing A-43's own `readback_mismatch` text
  // above (which honestly describes a container RESTART) — this feature
  // never restarts anything (`cscli allowlists` is a live runtime
  // operation, see crowdsec.py's "A-44 addendum" docstring section), so
  // reusing that wording here would itself be a dishonest claim.
  invalid_value: {
    ru: 'Некорректный IP-адрес или CIDR.',
    en: 'Invalid IP address or CIDR.',
  },
  allowlist_write_failed: {
    ru: 'CrowdSec отклонил команду — проверьте значение и повторите попытку.',
    en: 'CrowdSec rejected the command — check the value and try again.',
  },
  allowlist_readback_mismatch: {
    ru: 'Команда выполнена без ошибки, но повторное чтение белого списка не подтвердило изменение — попробуйте ещё раз.',
    en: 'The command ran without error, but a fresh read of the allowlist did not confirm the change — try again.',
  },
  allowlist_readback_unavailable: {
    ru: 'Изменение отправлено, но проверить результат не удалось — CrowdSec недоступен для чтения.',
    en: 'The change was sent, but the result could not be verified — CrowdSec is unavailable for reading.',
  },
  // A-55: `backup` console's own connector.reason codes
  // (services/backup/wiring.py::backup_connector_status) — the honest,
  // operator-actionable states behind the former always-«OK» backup banner
  // (GUI-прогон 2026-09-19, находка F1). Machine codes from the server,
  // translated here only (CLAUDE.md's localisation rule).
  backups_disabled: {
    ru: 'Резервное копирование выключено — включите BACKUP_ENABLED в .env и перезапустите приложение.',
    en: 'Backups are disabled — enable BACKUP_ENABLED in .env and restart the app.',
  },
  restic_binary_not_found: {
    ru: 'restic не найден в системе — установите его и убедитесь, что он доступен в PATH.',
    en: 'restic was not found on this system — install it and make sure it is on PATH.',
  },
  restic_password_missing: {
    ru: 'Пароль restic не настроен — задайте RESTIC_PASSWORD в .env.',
    en: 'The restic password is not configured — set RESTIC_PASSWORD in .env.',
  },
  restic_repo_missing: {
    ru: 'Каталог хранилища копий ещё не создан — выполните первую инициализацию репозитория restic.',
    en: 'The backup repository directory does not exist yet — run the initial restic repository setup.',
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
  lastStackStatus = null;
  lastStackSteps = null;
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
// A-51: `network`'s merged Отправлено/Получено column — was a raw byte
// count (`formatValue`), not legible at a glance for a typical connection's
// few-KB-to-MB volumes. `null` (traffic connector not configured/no
// baseline yet, see security_console.py._network_payload) stays the same
// honest dash `formatValue` already gives every other unavailable metric —
// this only changes the UNIT for genuinely-present numbers.
function formatBytesKb(bytes){
  if(bytes === null || bytes === undefined) return '—';
  return (bytes / 1024).toFixed(1);
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
// Замечание пользователя (2026-08-02): whole days between `iso` and now —
// used only for av's tile-colouring thresholds (last_scan_at/
// databases_updated_at) below. `null` (unparseable/missing) on purpose,
// never a fabricated 0 or Infinity — the same "None must never look like a
// real computed value" rule every other honest-null field in this app
// already follows.
function daysSinceIso(iso){
  if(!iso) return null;
  var date = new Date(iso);
  if(isNaN(date.getTime())) return null;
  var diffMs = Date.now() - date.getTime();
  return diffMs / (1000 * 60 * 60 * 24);
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
  // A-58: diagnostic hook (finding F4) — what language the opener runs in.
  console.debug('hranix-lang', 'openHealthScreen', currentLang());
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
  // A-58: diagnostic hook (finding F4) — the language this render pass used.
  console.debug('hranix-lang', 'renderHealthComponents', currentLang());
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
  // A-40: `network`'s engine list (security_console.py._network_payload)
  // now also carries `geoip` (offline country lookup, see that module's
  // docstring) alongside the already-labelled `crowdsec` (reputation
  // cross-reference, reused — not reimplemented — from `ids`, see that
  // same docstring).
  geoip: 'GeoIP (offline)',
  // A-28: perimeter's fifth source — rule-*listing* (pfctl -s rules /
  // netsh / iptables -S), a different call (and permission requirement)
  // than `os_firewall`'s on/off toggle above, so it gets its own label for
  // the connector-error banner.
  firewall_rules: 'Firewall rules',
  // A-38: perimeter's sixth source — current-network detection
  // (networksetup/nmcli/Get-NetConnectionProfile, see network_profile.py).
  network_profile: 'Network profile (OS)',
  // A-42: `ids`'s new «Белый список» section (security_console.py.
  // _ids_payload's `allowlist` key) — its own connector.status, separate
  // from `ids`'s own bouncer-key-backed `connector` (see crowdsec.py's
  // fetch_allowlists docstring for why the two can legitimately differ).
  allowlist: 'CrowdSec allowlist',
};

// Замечание пользователя (2026-07-31): общее правило подсветки плитки
// метрики для boolean-плиток вида «включена ли защита X» — true (защита
// включена) зелёным, false (выключена) красным, null (не проверялось)
// без подсветки — та же логика для firewall_active/disk_encryption_active
// ниже, вынесена один раз вместо двух одинаковых лямбд.
function boolTileVariant(value){
  if(value === true) return 'good';
  if(value === false) return 'bad';
  return null;
}

var CONSOLE_META = {
  perimeter: {
    icon: '🛡️',
    title: { ru: 'Защита периметра', en: 'Perimeter protection' },
    // Замечание пользователя (2026-07-31): «надо отразить эти текущие
    // цифры... чтобы было понятно, что всё работает, защита есть» — до
    // этого местные/мировые баны были видны ТОЛЬКО на графике за 7 дней
    // (и то не сразу, см. предыдущий фикс), без текущего числа прямо
    // сейчас. Теперь то же самое, что уже показывает консоль ids (те же
    // tipRu/tipEn), но короче для тесной плитки: local — сколько РЕАЛЬНО
    // произошло на этой машине (0 — хорошая новость, не «не считалось»),
    // community — контекст (мировой список CrowdSec, не про эту машину).
    metricsSectionTitle: { ru: 'Состояние защиты', en: 'Protection status' },
    metricLabels: {
      // Замечание пользователя (2026-07-31): «состояние Да — зелёный
      // (фаервол включён)» — тот же принцип для шифрования дисков (тоже
      // boolean-плитка «включена ли защита»), не только для фаервола.
      firewall_active: { ru: 'Фаервол', en: 'Firewall', tileVariant: boolTileVariant },
      disk_encryption_active: { ru: 'Шифрование дисков', en: 'Disk encryption', tileVariant: boolTileVariant },
      active_bans_local: {
        ru: 'Местных банов', en: 'Local bans',
        tipRu: 'Реальные решения, принятые этой машиной (вручную или по сценарию обнаружения) — то, что действительно произошло здесь. 0 — хороший, честный результат, а не «не проверялось».',
        tipEn: 'Real decisions made by this machine itself (manually or via a detection scenario) — what actually happened here. 0 is a genuinely good result, not "not checked".',
        // Местные баны — красным, если есть хоть один (реальная угроза
        // именно на этой машине), зелёным при честном 0, без подсветки
        // при null (не проверялось — CrowdSec не настроен/недоступен).
        tileVariant: function(value){
          if(value === 0) return 'good';
          if(typeof value === 'number' && value > 0) return 'bad';
          return null;
        },
      },
      active_bans_community: {
        ru: 'Мировой список', en: 'Global list',
        tipRu: 'IP-адреса, заблокированные по данным всего сообщества CrowdSec по всему миру — не обязательно атаковали именно эту машину.',
        tipEn: 'IP addresses blocked based on data from the whole CrowdSec community worldwide — not necessarily attacks against this specific machine.',
        // Всегда приглушённая — большое число, но не про эту машину, не
        // тревожный сигнал ни при каком значении (в отличие от местных).
        tileVariant: function(){ return 'muted'; },
      },
      open_ports: { ru: 'Открытых портов', en: 'Open ports' },
      firewall_rules: { ru: 'Правил фаервола', en: 'Firewall rules' },
    },
    // A-26: retitled to match what the chart actually shows — real
    // last-7-days history (see security_console.py._perimeter_payload) —
    // the old title ("Заблокировано входящих · 24 часа") described a 24h
    // blocked-incoming-events number this project has never had a data
    // source for at all; charting that title against different data would
    // repeat exactly the "real number, wrong label" confusion A-23 fixed
    // for `ids`. Post-merge user question (2026-07-31): this console's
    // chart is now TWO series (`values_community`/`values_local`, see
    // renderConsoleChart/drawGroupedBarChart) instead of one summed bar —
    // every other console's chart is still the single `values` shape.
    chartTitle: { ru: 'Активные баны CrowdSec · 7 дней', en: 'CrowdSec active bans · 7 days' },
    // A-31: the per-port detail list (`ports`, see
    // security_console.py._perimeter_payload) `metrics.open_ports` used to
    // summarize into a bare count with no way to see WHICH ports or whose
    // process — the user's own complaint this task fixes ("31 — а какие,
    // кем, где статистика?"). Rendered via its own `renderConsoleList`
    // branch below (`lastConsoleId === 'perimeter'`), same pattern as
    // `ids`'s `recent_attempts`/`network`'s `connections`.
    listKey: 'ports',
    listTitle: { ru: 'Открытые порты', en: 'Open ports' },
    actions: [
      // A-36: previously a disabled placeholder (A-28/A-31) explaining
      // that this app never escalates its own privileges wholesale — now
      // a REAL action: each click triggers its own one-time, visible OS
      // admin-password prompt (elevated.py's `elevated_run`, same
      // already-reviewed `osascript ... with administrator privileges`
      // pattern as A-25's Wazuh-agent installer), never a standing
      // escalation of the running app itself (see plan document's
      // "Важное решение" section). `danger: true` gives this button its
      // own alarming red style (see renderConsole()'s action loop below)
      // — wide blast radius, may cut off legitimate local services — and
      // `handleBlockAllIncoming` requires an explicit `window.confirm()`
      // before ever calling the endpoint, same pattern as A-29's
      // CrowdSec-ban confirmation.
      {
        id: 'block_all_incoming', danger: true,
        busyRu: 'Блокируем входящие…', busyEn: 'Blocking incoming…',
        ru: '🔒 Заблокировать все входящие', en: '🔒 Block all incoming',
        tipRu: 'Запросит пароль администратора (разовое системное окно — права не сохраняются после выполнения) и заблокирует ВЕСЬ входящий трафик. Может отрезать легитимные локальные сервисы (общий доступ к файлам, удалённые подключения).',
        tipEn: 'Prompts for an administrator password (a one-time system dialog — no privilege is kept afterward) and blocks ALL incoming traffic. May cut off legitimate local services (file sharing, remote connections).',
      },
      { id: 'unblock_all_incoming', ru: 'Разблокировать все входящие', en: 'Unblock all incoming', busyRu: 'Снимаем блокировку…', busyEn: 'Unblocking…' },
      { id: 'rescan_ports', ru: 'Пересканировать порты', en: 'Rescan ports', busyRu: 'Пересканируем порты…', busyEn: 'Rescanning ports…' },
      // A-36: previously a disabled placeholder (A-28/A-31) — now a real
      // action, same one-time elevated-prompt mechanism as
      // block_all_incoming above. A second click (while the list is
      // already showing) hides it again — same toggle pattern
      // handleShowQuarantine already uses for `av`'s quarantine list.
      {
        id: 'firewall_rules',
        busyRu: 'Читаем правила…', busyEn: 'Reading rules…',
        ru: 'Правила фаервола', en: 'Firewall rules',
        tipRu: 'Запросит пароль администратора (разовое системное окно) и покажет реальный вывод «pfctl -s rules» (macOS) / аналог на Linux/Windows.',
        tipEn: 'Prompts for an administrator password (a one-time system dialog) and shows the real "pfctl -s rules" (macOS) output / the Linux/Windows equivalent.',
      },
    ],
    settingLabels: {
      // Замечание пользователя (2026-07-31): раньше показывало голое
      // "standard" без пояснения, что входит в этот профиль, и без
      // намёка, что переключать пока не на что — сервер всегда шлёт один
      // и тот же жёстко зашитый профиль (security_console.py._perimeter_
      // payload), реального переключения между профилями сейчас нет.
      // Честная подпись вместо этого: `tipRu`/`tipEn` на самой метке прямо
      // говорит «единственный профиль, переключения пока нет», а `values`
      // (тот же code -> {ru,en} паттерн, что и `ids`'s `ban_policy` выше)
      // расшифровывает, что конкретно означает «Стандартный» — те самые
      // три настройки ниже, а не выдуманное описание.
      protection_profile: {
        ru: 'Профиль защиты', en: 'Protection profile',
        tipRu: 'Единственный профиль, который сейчас реализован — переключения между профилями пока нет.',
        tipEn: 'The only profile currently implemented — there is no profile switching yet.',
        values: {
          standard: {
            ru: 'Стандартный: автоблокировка новых входящих и уведомления о новых открытых портах включены, обязательный VPN вне доверенной сети выключен (см. три настройки ниже)',
            en: 'Standard: auto-block of new incoming connections and notifications on new open ports are on, mandatory VPN outside a trusted network is off (see the three settings below)',
          },
        },
      },
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
      // A-23: a real user saw the old single `active_bans` tile ("16673
      // активных банов") with no explanation and reasonably concluded the
      // panel was broken/unusable — the number was real but was almost
      // entirely CrowdSec's global community blocklist, not local activity
      // (see crowdsec.py's "A-23 addendum" docstring for the live
      // investigation). Split into two explicit, separately-labelled
      // metrics with a `tipRu`/`tipEn` tooltip each (same pattern already
      // used for `actions[].tipRu/tipEn` below) — the tooltip text is the
      // fix, not just the split, since a differently-labelled-but-still-
      // unexplained number would repeat the same mistake.
      active_bans_community: {
        ru: 'Заблокировано глобально (community-лист CrowdSec)',
        en: 'Blocked globally (CrowdSec community list)',
        tipRu: 'IP-адреса, заблокированные по данным всего сообщества CrowdSec по всему миру — не обязательно атаковали именно эту машину.',
        tipEn: 'IP addresses blocked based on data from the whole CrowdSec community worldwide — not necessarily attacks against this specific machine.',
      },
      active_bans_local: {
        ru: 'Реальные попытки на этой машине',
        en: 'Real attempts on this machine',
        tipRu: 'Решения, инициированные локально на этой машине (вручную через cscli или сценарием обнаружения) — то, что реально произошло здесь.',
        tipEn: 'Decisions initiated locally on this machine (manually via cscli or by a detection scenario) — what actually happened here.',
      },
      scenarios: { ru: 'Сценариев (правил)', en: 'Scenarios (rules)' },
      last_event_at: { ru: 'Последнее событие', en: 'Last event' },
    },
    chartTitle: { ru: 'Попытки вторжений · 7 дней', en: 'Intrusion attempts · 7 days' },
    listKey: 'recent_attempts',
    listTitle: { ru: 'Последние попытки', en: 'Recent attempts' },
    actions: [
      // Замечание пользователя (2026-07-25): убран мёртвый top-level
      // "Разбанить IP" placeholder, который раньше здесь был (A-29) —
      // в отличие от «Обновить сценарии» (было честно задизейблено, но
      // представляло РЕАЛЬНОЕ единое действие, заблокированное только
      // архитектурой, и позже включено, A-43), эта кнопка структурно
      // никогда не могла заработать сама по себе (разбан — всегда
      // действие над КОНКРЕТНОЙ записью, без выбранного IP кнопке
      // нечего делать) — чистое дублирование уже существующей кнопки
      // «Разбанить» на каждой строке ниже (renderConsoleList's `ids`
      // branch), без своей ценности, только путало.
      { id: 'crowdsec_ban', ru: 'Забанить вручную', en: 'Ban manually' },
      // A-43: previously a disabled `soon` placeholder explaining "порог
      // настраивается отдельно для каждого сценария, поменять можно только
      // руками" — now a REAL action: opens a modal listing every real
      // installed scenario's capacity/leakspeed, each independently
      // editable via its OWN one-shot elevated `docker exec`/`docker
      // compose restart` (see crowdsec.py's "A-43 addendum" docstring and
      // docs/план-спецификация-фаза-0-порог-сценариев-2026-07-24.md's
      // "Важное архитектурное решение" for exactly why this narrow
      // exception to "никогда docker exec" is safe — a visible, never-
      // cached OS admin prompt on every single change, the same
      // elevated_run() A-36's firewall actions already use).
      {
        id: 'scenario_thresholds', ru: 'Показать/изменить пороги', en: 'Show/edit thresholds',
        tipRu: 'Каждое изменение запросит пароль администратора (разовое системное окно — права не сохраняются после выполнения) и перезапустит контейнер CrowdSec, чтобы применить новое значение.',
        tipEn: 'Every change prompts for an administrator password (a one-time system dialog — no privilege is kept afterward) and restarts the CrowdSec container to apply the new value.',
      },
      // A-45: REVISES the A-43 decision above ("Обновить сценарии...
      // deliberately does NOT get this same treatment") — not a silent
      // reversal, see crowdsec.py's own "A-45 addendum" docstring section
      // and docs/план-спецификация-фаза-0-обновление-сценариев-2026-07-25.md's
      // "Пересмотр решения A-43". `cscli hub update`/`upgrade` still pulls
      // third-party content from hub.crowdsec.net — that risk has not gone
      // away — but a real, official CrowdSec preview flag (`cscli hub
      // upgrade --dry-run`) was found that shows the operator exactly what
      // would be installed BEFORE it is installed, narrowing (not
      // eliminating) that risk enough to enable a two-step "Проверить" →
      // "Применить" UX instead of a single one-click "Обновить" (see
      // renderScenarioUpdatesSection/handleCheckScenarioUpdates/
      // handleApplyScenarioUpdates below).
      {
        id: 'scenario_updates_check', ru: 'Проверить обновления', en: 'Check for updates',
        busyRu: 'Проверяем обновления…', busyEn: 'Checking for updates…',        tipRu: 'A-45 (пересматривает решение A-43): запросит пароль администратора (разовое системное окно) и покажет РЕАЛЬНЫЙ план CrowdSec (cscli hub upgrade --dry-run) — что будет установлено, ДО того как это установится. Ничего не устанавливается на этом шаге. Установка — отдельный следующий шаг («Применить обновления»), появляется только если план показал реальные апгрейды. Честный остаток риска: CrowdSec всё ещё скачивает каталог с hub.crowdsec.net при каждой проверке — если сам hub.crowdsec.net скомпрометирован, локально это обнаружить нельзя (см. README раздел 6.2).',
        tipEn: 'A-45 (revises the A-43 decision): prompts for an administrator password (a one-time system dialog) and shows CrowdSec\'s REAL plan (cscli hub upgrade --dry-run) — what would be installed, before it is installed. Nothing is installed at this step. Installing is a separate following step ("Apply updates"), shown only if the plan shows real upgrades. Honest residual risk: CrowdSec still downloads its catalogue from hub.crowdsec.net on every check — if hub.crowdsec.net itself were compromised, no local check could catch that (see README section 6.2).',
      },
      // A-44: «Добавить в белый список» is no longer a disabled placeholder
      // here — it is a real inline form (value + comment) inside the
      // idsAllowlistSection below (see handleAddToAllowlist), the same
      // "own section, not a generic action button" shape A-33's own
      // «Проверить папку» already established for `av` (that console's
      // `actions` array never had a "Scan a folder" entry either — grep
      // CONSOLE_META.av.actions to confirm).
    ],
    // A-42: `whitelist_count`/`ban_threshold`/`ban_duration_hours` used to
    // be hardcoded A-11 numbers, never read from real CrowdSec and never
    // editable — see security_console.py._ids_payload's own docstring for
    // why. `whitelist_count` is gone entirely (the real data is now the
    // `allowlist` section rendered below, not a settings-panel number).
    // `ban_threshold`/`ban_duration_hours` are replaced by one honest
    // `ban_policy` key — the server sends only the machine-readable code
    // `"per_scenario"` (CLAUDE.md's localisation rule: no server-side
    // phrasing), translated here via `values` — the same
    // code -> {ru,en} lookup shape `ERROR_MESSAGES`/`ID_KIND_LABELS`
    // already use elsewhere in this file, just scoped to one setting
    // instead of a whole error/id-kind vocabulary. renderConsole()'s
    // settings loop checks for `.values` before falling back to plain
    // `formatValue`.
    settingLabels: {
      ban_policy: {
        ru: 'Порог / длительность бана', en: 'Ban threshold / duration',
        values: {
          per_scenario: {
            ru: 'Настраивается отдельно для каждого сценария обнаружения — единого порога/длительности не существует',
            en: 'Configured separately per detection scenario — there is no single global threshold/duration',
          },
        },
      },
      rule_source: {
        ru: 'Источник правил', en: 'Rule source',
        tipRu: 'Единственный источник правил, который вообще настроен в этом проекте — не значение, прочитанное из CrowdSec.',
        tipEn: 'The only rule source this project actually configures — not a value read from CrowdSec.',
      },
    },
  },
  av: {
    icon: '🦠',
    title: { ru: 'Вирусная активность', en: 'Virus activity' },
    // Замечание пользователя (2026-08-02): подсветка плиток по смыслу
    // значения (тот же tileVariant-механизм, что и у perimeter) + честный
    // порог "давно не проверялось"/"базы устарели" — конкретные days-ago
    // границы из просьбы пользователя.
    metricLabels: {
      clean: { ru: 'Угроз не найдено', en: 'No threats found' },
      last_scan_at: {
        ru: 'Последняя проверка', en: 'Last scan',
        tipRu: 'Зелёная — проверялось не позже 3 дней назад. Жёлтая — от 3 до 7 дней. Красная — больше 7 дней назад или ни разу.',
        tipEn: 'Green — scanned within the last 3 days. Yellow — 3 to 7 days ago. Red — more than 7 days ago, or never.',
        // Реальный баг, найден пользователем живьём (2026-08-16): «никогда
        // не проверялось» (days === null, прочерк на плитке) раньше не
        // подсвечивался вообще — хотя по смыслу это как минимум так же
        // тревожно, как «больше 7 дней назад» (собственная подсказка выше
        // это и утверждает). Симметрично для databases_updated_at ниже.
        tileVariant: function(value){
          var days = daysSinceIso(value);
          if(days === null) return 'bad';
          if(days > 7) return 'bad';
          if(days > 3) return 'warn';
          return 'good';
        },
      },
      quarantine_count: {
        ru: 'В карантине', en: 'In quarantine',
        // Замечание пользователя (2026-08-02): 0 — нейтральная (белая,
        // обычная плитка), НЕ зелёная — «ничего в карантине» не настолько
        // значимое событие, чтобы специально подсвечивать; только
        // непустой карантин (реальная угроза) подсвечивается красным.
        tileVariant: function(value){
          if(typeof value !== 'number' || value === 0) return null;
          return 'bad';
        },
      },
      databases_updated_at: {
        ru: 'Базы обновлены', en: 'Databases updated',
        tipRu: 'Зелёная — обновлялись не позже 1 дня назад. Жёлтая — от 1 до 3 дней. Красная — больше 3 дней назад или ни разу.',
        tipEn: 'Green — updated within the last day. Yellow — 1 to 3 days. Red — more than 3 days ago, or never.',
        tileVariant: function(value){
          var days = daysSinceIso(value);
          if(days === null) return 'bad';
          if(days > 3) return 'bad';
          if(days > 1) return 'warn';
          return 'good';
        },
      },
    },
    // A-26: retitled to match metrics.quarantine_count, the real field
    // now charted (see security_console.py._av_payload's docstring for
    // why quarantine_count was chosen over a "files scanned" count).
    chartTitle: { ru: 'В карантине · 7 дней', en: 'Quarantined items · 7 days' },
    actions: [
      { id: 'quick_scan', ru: 'Быстрая проверка', en: 'Quick scan', busyRu: 'Сканирование…', busyEn: 'Scanning…' },
      { id: 'full_scan', ru: 'Полная проверка', en: 'Full scan', busyRu: 'Сканирование…', busyEn: 'Scanning…' },
      // Замечание пользователя (2026-08-02): «Проверить папку» переехала
      // сюда из отдельной инлайн-секции — открывает модалку с реальным
      // нативным выбором папки (см. index.html's avCustomScanModalOverlay,
      // handleOpenCustomScanModal).
      { id: 'custom_scan', ru: 'Проверить папку', en: 'Scan a folder' },
      // A-27: honestly renamed from "Обновить базы"/"Update databases" —
      // clamd's own protocol can only re-read signature files already on
      // its disk (`RELOAD`), never fetch new ones from the internet (that
      // is `freshclam`'s job, a separate process inside the container this
      // connector cannot trigger — see ClamdClient.reload's docstring).
      // The old label implied the more powerful (and untrue) capability.
      {
        id: 'reload_databases', ru: 'Перечитать базы', en: 'Reread databases',
        busyRu: 'Перечитываем базы…', busyEn: 'Rereading databases…',        tipRu: 'Перечитывает уже скачанные на диск базы сигнатур — НЕ скачивает новые из интернета.',
        tipEn: 'Rereads signature databases already downloaded to disk — does NOT download new ones from the internet.',
      },
      // Замечание пользователя (2026-08-02): это — то самое «скачать новые
      // из интернета», которого «Перечитать базы» выше честно не делает.
      // Реальный elevated docker exec freshclam (см. clamav.py's
      // update_clamav_databases), тот же узкий прецедент, что и у CrowdSec
      // (A-43/A-45) — разовая кнопка, никогда не расписание (см. этой
      // функции собственный докстринг за причиной).
      {
        id: 'update_databases', ru: '⬇️ Обновить базы', en: '⬇️ Update databases',
        busyRu: 'Обновляем базы…', busyEn: 'Updating databases…',        tipRu: 'Запросит пароль администратора (разовое системное окно) и скачает свежие базы сигнатур из интернета через freshclam внутри контейнера ClamAV.',
        tipEn: 'Prompts for an administrator password (a one-time system dialog) and downloads fresh signature databases from the internet via freshclam inside the ClamAV container.',
      },
      { id: 'show_quarantine', ru: 'Карантин', en: 'Quarantine' },
    ],
    // Замечание пользователя (2026-08-02): «Защита в реальном времени»/
    // «Проверять съёмные носители» убраны совсем — ни on-access
    // сканирования, ни определения подключения съёмных носителей в этом
    // проекте не существует (см. clamav.py's module docstring и это
    // задание собственное исследование), выдумывать переключатель без
    // возможности за ним ничего не стояло бы дальше той же самой
    // нечестности, что уже чинилась для perimeter's "Профиль защиты".
    // «Действие при угрозе» — оставлено, но честно нередактируемо (только
    // «Карантин» реально реализован). «Расписание полной проверки» —
    // теперь настоящее, кликабельно (см. onClick/formatValue ниже).
    settingLabels: {
      action_on_threat: {
        ru: 'Действие при угрозе', en: 'Action on threat',
        tipRu: 'Карантин — единственное реализованное действие сейчас: файл перемещается в карантин, без возможности удаления. «Блокировка»/«Удаление» не реализованы.',
        tipEn: 'Quarantine is the only implemented action right now: the file is moved to quarantine, deletion is not supported. "Block"/"Delete" are not implemented.',
        values: {
          quarantine: { ru: 'Карантин', en: 'Quarantine' },
        },
      },
      full_scan_schedule: {
        ru: 'Расписание полной проверки', en: 'Full scan schedule',
        tipRu: 'Нажмите, чтобы включить/выключить и настроить время автоматической полной проверки.',
        tipEn: 'Click to enable/disable and configure the time of the automatic full scan.',
        formatValue: function(value, lang){
          if(!value || !value.enabled) return lang === 'ru' ? 'выключено' : 'off';
          var hh = String(value.hour).padStart(2, '0');
          var mm = String(value.minute).padStart(2, '0');
          var days = value.days || [];
          var daysText;
          if(days.length === 7){
            daysText = lang === 'ru' ? 'ежедневно' : 'every day';
          } else if(days.length === 0){
            daysText = lang === 'ru' ? 'дни не выбраны' : 'no days selected';
          } else if(days.length === 5 && [0,1,2,3,4].every(function(d){ return days.indexOf(d) !== -1; })){
            daysText = lang === 'ru' ? 'по будням' : 'weekdays';
          } else {
            daysText = days.slice().sort().map(function(d){ return AV_SCHEDULE_DAY_LABELS[d][lang]; }).join(', ');
          }
          return daysText + (lang === 'ru' ? ' в ' : ' at ') + hh + ':' + mm + ' UTC';
        },
        onClick: function(){ handleOpenAvScheduleModal(); },
      },
    },
  },
  network: {
    icon: '📡',
    title: { ru: 'Сеть', en: 'Network' },
    metricLabels: {
      outbound_traffic_status: { ru: 'Исходящий трафик', en: 'Outbound traffic' },
      active_connections: { ru: 'Активных соединений', en: 'Active connections' },
      // A-40: real count now (was a hardcoded 0) — cross-referenced against
      // CrowdSec's currently active decisions (security_console.py's
      // `_network_payload`). The tooltip explains the honest "—" case: it
      // means "not checked" (CrowdSec not configured/unreachable), never
      // "checked, zero found" — same "None must never look like a clean
      // 0" rule as `ids`'s own metrics.
      suspicious_connections: {
        ru: 'Подозрительных', en: 'Suspicious',
        tipRu: '«—» значит «не проверено» (CrowdSec не настроен/недоступен), а не «проверено, угроз нет».',
        tipEn: '"—" means "not checked" (CrowdSec not configured/unreachable), not "checked, none found".',
      },
      dns_leak_detected: { ru: 'Утечка DNS', en: 'DNS leak' },
    },
    // A-26: retitled — this console never had a traffic-VOLUME data
    // source (no such engine exists, see security_console.py's
    // docstring), so "Трафик · последний час" described a number that
    // was never real. Retitled to match metrics.active_connections, the
    // field genuinely charted now.
    chartTitle: { ru: 'Активные соединения · 7 дней', en: 'Active connections · 7 days' },
    listKey: 'connections',
    listTitle: { ru: 'Активные соединения', en: 'Active connections' },
    // A-54: real user request (2026-08-17) — «Разорвать соединение»/
    // «Блокировать процесс» here were dead disabled placeholders (A-30's
    // own "never real for a generic click" reasoning below no longer
    // applies: A-52/A-53 built the real thing, but scoped to a SPECIFIC
    // connection's own row/modal — not a bare button with no target here).
    // Removed rather than left disabled — a disabled button whose real
    // equivalent now exists elsewhere would be actively misleading, not
    // just inert. `export_log` moved out too, see the dedicated button next
    // to #conListTitle (index.html) instead — this console has NO actions
    // left at all now, so renderConsole() hides the whole «Управление»
    // section for it (see that function's own A-54 comment).
    actions: [],
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
      { id: 'create_snapshot', ru: '💾 Создать полную копию', en: '💾 Create full backup', busyRu: 'Создаём копию…', busyEn: 'Creating backup…' },
      { id: 'restore_system', ru: 'Восстановить систему…', en: 'Restore system…', busyRu: 'Восстанавливаем…', busyEn: 'Restoring…' },
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
    // A-35: a real user opening this console saw meaningful Russian FIM
    // descriptions (`entries[].description`, see wazuh.py's `_finding_to_entry`)
    // but no explanation of WHAT is being watched or WHY — read as
    // "unexplained noise", not "the app is watching itself for tampering".
    // Same `{ru, en}` static-text convention as every other label in this
    // file (`chartTitle`/`listTitle` above) — rendered once in
    // `renderConsole()` into `#conListHint`, hidden for every console that
    // has no `listHint` (see that element's own comment in index.html).
    listHint: {
      ru: 'Что это: система отслеживает изменения важных файлов самого приложения и ключевых системных путей — если файл меняется без вашего ведома, это может быть признаком проблемы.',
      en: 'What this is: the system watches for changes to important files of the app itself and key system paths — if a file changes without your knowledge, that can be a sign of a problem.',
    },
    actions: [
      {
        ru: '🤖 Анализ ассистентом', en: '🤖 Assistant analysis', soon: true,
        tipRu: 'Скоро — требует ИИ-ассистента (Фаза 2+), не реализовано в Фазе 0',
        tipEn: 'Coming soon — requires the AI assistant (Phase 2+), not implemented in Phase 0',
      },
      // A-30: real on-demand Wazuh FIM rescan — live-verified against this
      // deployment's actual manager (see wazuh.py's WazuhClient.trigger_syscheck
      // docstring: the real request shape turned out to differ from the
      // Wazuh REST API's own documented one).
      { id: 'trigger_syscheck', ru: 'Запустить FIM-скан', en: 'Run FIM scan', busyRu: 'Запускаем FIM-скан…', busyEn: 'Running FIM scan…' },
      // A-30: universal export mechanism (server/app/services/security_console_export.py),
      // shared with `network`'s identical action below via the same
      // ACTION_HANDLERS.export_log handler — not two separate code paths.
      { id: 'export_log', ru: 'Экспорт журнала', en: 'Export log' },
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
  // A-56: честная подпись — эта плитка показывает (ids, active_bans_local)
  // (последний сэмпл сэмплера), а не «всё заблокированное за сутки»; ключ
  // blocked_24h оставлен для совместимости контракта /security/overview.
  { key: 'blocked_24h', ru: 'Активных локальных банов', en: 'Active local bans' },
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
  // A-38: the network-profile background monitor's own "nudge, never an
  // automatic elevated firewall call" notification (see network_profile.py's
  // docstring's "переключение уровня защиты" section) — an invitation to
  // click "🔒 Заблокировать все входящие" (A-36) manually, not a claim that
  // anything was blocked automatically.
  if(entry.topic === 'security.alert' && payload.reason === 'public_network_detected'){
    return (lang === 'ru'
      ? 'Обнаружена публичная сеть: ' + (payload.display_name || payload.network_key || '') +
        ' — рассмотрите ручную блокировку входящих в консоли «Периметр».'
      : 'Public network detected: ' + (payload.display_name || payload.network_key || '') +
        ' — consider manually blocking incoming traffic from the Perimeter console.');
  }
  // Замечание пользователя (2026-08-02): реальное уведомление (не только
  // баннер в самой консоли «Вирусная активность») при каждом реальном
  // перемещении файла в карантин — см. clamav.py's quarantine_file.
  if(entry.topic === 'security.alert' && payload.reason === 'file_quarantined'){
    return (lang === 'ru'
      ? '🦠 Файл помещён в карантин: ' + (payload.original_path || '') +
        (payload.signature ? ' (' + payload.signature + ')' : '')
      : '🦠 File quarantined: ' + (payload.original_path || '') +
        (payload.signature ? ' (' + payload.signature + ')' : ''));
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
  // A-63-5 (live full-stack finding, 2026-09-21 — «висит информация от
  // старого»): the first fetch of a console can take seconds (real
  // osquery/Wazuh calls with the full stack up), and until then the screen
  // showed the PREVIOUS console's header and data blocks. Now: the header
  // switches immediately (title/icon from CONSOLE_META, engine «…»), the
  // previous console's data blocks are hidden outright, and a pulsing
  // «Обновляется…» label fills the gap until the real render (or the error
  // handlers) turn it off.
  var meta = CONSOLE_META[id];
  var lang = currentLang();
  document.getElementById('conIcon').textContent = meta ? meta.icon : '';
  document.getElementById('conTitle').textContent = meta ? meta.title[lang] : '';
  document.getElementById('conEngine').textContent = '…';
  document.getElementById('conUpdating').hidden = false;
  ['conListSection', 'conChartCard', 'conMapCard'].forEach(function(blockId){
    var block = document.getElementById(blockId);
    if(block) block.hidden = true;
  });
  // A-27: a fresh console open always starts with the quarantine panel
  // collapsed and any previous console's full-scan poll stopped — neither
  // should leak across console switches (e.g. leaving `av` mid-full-scan
  // and reopening it later should not resume a stale poll loop against a
  // job the operator may not even care about anymore).
  stopAvFullScanPoll();
  avQuarantineVisible = false;
  lastQuarantineItems = null;
  // A-33: same "reset on every fresh open, don't leak across console
  // switches" reasoning as the quarantine state above — a previous av
  // visit's scan history must not flash on a different console for a
  // moment before its own real data loads.
  lastScanHistoryItems = null;
  // A-39: same reasoning again — a previous `network` visit's auto-refresh
  // timer must never keep ticking (and re-fetching) after the operator has
  // navigated away, whether to another console or back to the overview.
  // `startNetworkPolling()` (called below, only for `id === 'network'`)
  // clears any existing timer itself too, but resetting unconditionally
  // here — same belt-and-suspenders redundancy `stopAvFullScanPoll()` above
  // already gets — means even a code path that skips the `id === 'network'`
  // branch below can never leave a stale timer running.
  stopNetworkPolling();
  // A-36: same reasoning again — a previous perimeter visit's elevated
  // rule-list view must not stay open (and stale) across a console switch.
  perimeterRulesVisible = false;
  lastFirewallRules = null;
  // A-37: same reasoning again — a previous perimeter visit's open
  // port-detail modal must not stay open across a console switch.
  closePortModal();
  // A-53: same reasoning again — a previous `network` visit's open
  // connection-detail modal must not stay open across a console switch.
  closeConnectionModal();
  // Post-merge review fix (A-45): same reasoning again — a previous `ids`
  // visit's open scenario-updates plan/button must not stay visible (and
  // stale, with a live "Apply updates" button) across a console switch
  // without a fresh elevated check.
  idsScenarioUpdatesVisible = false;
  lastScenarioUpdatePlan = null;
  show('view-console');
  var errBox = document.getElementById('conError');
  errBox.hidden = true;
  // Cleared here (once, when a console is freshly opened) rather than in
  // renderConsole() itself: refreshBackupConsole() also calls
  // renderConsole() right after a snapshot/restore action completes, and
  // that call must NOT wipe the status message the action just set.
  setConActionStatus(null);
  // A-54: same reasoning as setConActionStatus(null) above — a previous
  // `network` visit's export-result message must not flash on a different
  // console for a moment before its own real data loads.
  setConActionStatus(null, null, 'conListExportStatus');
  setCustomScanStatus(null);
  setNetworkProfileStatus(null);
  try{
    var res = await apiFetch(CONSOLE_ROUTES[id]);
    if(!res.ok){
      var body = await res.json().catch(function(){ return {}; });
      var code = (body.detail && body.detail.error) || 'unknown_error';
      errBox.textContent = translateError(code);
      errBox.hidden = false;
      // A-63-5: the real data never arrives on this path — stop the label.
      document.getElementById('conUpdating').hidden = true;
      return;
    }
    lastConsoleData = await res.json();
    renderConsole();
    // A-33: real, persistent scan history — a separate endpoint from `GET
    // .../av` itself (same "only fetched when actually needed" reasoning
    // as the quarantine list, see handleShowQuarantine), except this one
    // loads eagerly (not behind a button) since it is meant to be visible
    // as soon as the console opens, not an on-demand drill-down.
    if(id === 'av') fetchAndRenderScanHistory();
    // A-39 (11а): `network` is the one console meant to feel like a live
    // dashboard, not a "snapshot on open" — real TCP/UDP connections churn
    // on a human timescale, and this task's own DoD is "wait ~10s without
    // clicking anything, confirm the data moved on its own". Started only
    // after the console's first real load succeeds (never against a
    // console showing an error banner) and only for `network` itself —
    // every other console keeps A-11's original "reload on click/action"
    // behavior unchanged, exactly this task's brief.
    if(id === 'network') startNetworkPolling();
  } catch(e){
    errBox.textContent = translateError('network_error');
    errBox.hidden = false;
    // A-63-5: no render will follow a network-level failure — stop the label.
    document.getElementById('conUpdating').hidden = true;
  }
}

function closeConsole(){
  stopAvFullScanPoll();
  stopNetworkPolling();
  lastConsoleId = null;
  lastConsoleData = null;
  show('view-overview');
  loadOverview(); // pick up any toggle made while inside the console
}

// A-39 (11а): auto-refresh for the `network` console — a plain `setInterval`
// (this task's own brief: "простой setInterval ..., не WebSocket/SSE", same
// no-push-infrastructure call A-13 already made), same start/stop shape
// `startHealthPolling`/`stopHealthPolling` already use for the health pill
// above (`stop` first, then set a fresh interval — never two timers alive at
// once) and the same check-then-null stop discipline `stopAvFullScanPoll()`
// uses. Kept to a "few seconds" cadence per this task's own brief ("не
// агрессивный поллинг") — frequent enough to visibly move within the DoD's
// ~10s observation window, not so frequent it hammers osquery/nettop with a
// fresh subprocess spawn every second.
var NETWORK_POLL_INTERVAL_MS = 5000;
var networkPollTimer = null;

// A-63-3 (live full-stack finding, 2026-09-21): a network fetch that takes
// LONGER than the 5s poll interval (a slow osqueryi scan under load — on
// the owner's machine it could exceed even 15s) used to stack: every tick
// fired a fresh request while the previous ones were still running, the
// parallel osqueryi children then starved the machine and timed each other
// out — a self-inflicted `unreachable` storm that, among other things,
// blanked the connections map. Skip a tick entirely while the previous
// request is still in flight; the interval keeps ticking either way.
var networkRefreshInFlight = false;

function stopNetworkPolling(){
  if(networkPollTimer){ clearInterval(networkPollTimer); networkPollTimer = null; }
}
function startNetworkPolling(){
  stopNetworkPolling();
  networkPollTimer = setInterval(refreshNetworkConsole, NETWORK_POLL_INTERVAL_MS);
}
async function refreshNetworkConsole(){
  // Extra safety net (mirrors refreshAvConsole/refreshIdsConsole/
  // refreshPerimeterConsole's own identical guard below): if this ever
  // fires after the operator has navigated away despite stopNetworkPolling()
  // having been called, self-heal by stopping instead of re-fetching/
  // re-rendering a console that is no longer on screen.
  if(lastConsoleId !== 'network'){ stopNetworkPolling(); return; }
  if(networkRefreshInFlight){ return; }
  networkRefreshInFlight = true;
  try{
    var res = await apiFetch(CONSOLE_ROUTES.network);
    if(!res.ok) return;
    lastConsoleData = await res.json();
    renderConsole(); // rebuilds #conList (the connections table) too — does not touch #conActionStatus
  } catch(e){ /* network hiccup — keep showing the last known console data, next tick retries */ }
  finally {
    networkRefreshInFlight = false;
  }
}

function renderConsole(){
  if(!lastConsoleId || !lastConsoleData) return;
  var meta = CONSOLE_META[lastConsoleId];
  var lang = currentLang();

  // A-63-5: real data has arrived — the «Обновляется…» label's job is done
  // (openConsole turned it on; every render path — first load, refresh
  // button, auto-poll — lands here, so this is the single reliable place
  // to turn it off).
  var updatingLabel = document.getElementById('conUpdating');
  if(updatingLabel) updatingLabel.hidden = true;

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
  // A-63-7: when the banner's os_counters line is the honest
  // `not_configured` (always true on Windows), the whole banner gets the
  // full explanation as its tooltip — the line itself stays short.
  var osCountersBannerTip = '';
  if(lastConsoleData.connector && lastConsoleData.connector.status !== 'ok'){
    // A-55: a connector MAY carry its own machine-readable `reason` (the
    // backup console's backup_connector_status does) — prefer that specific,
    // operator-actionable code over the generic `connector_<status>` text.
    connectorLines.push(
      translateError(lastConsoleData.connector.reason || ('connector_' + lastConsoleData.connector.status))
    );
  }
  if(lastConsoleData.connectors){
    Object.keys(lastConsoleData.connectors).forEach(function(key){
      var c = lastConsoleData.connectors[key];
      if(c && c.status && c.status !== 'ok'){
        var label = TOOL_LABELS[key] || key;
        // A-41-fix: `firewall_rules`'s permission_denied has a real,
        // in-app one-shot fix (the «Правила фаервола» button, A-36) —
        // use the connector-specific actionable wording instead of the
        // generic "run elevated" dead-end message (see ERROR_MESSAGES'
        // own comment on `connector_permission_denied_firewall_rules`).
        var errorKey = (key === 'firewall_rules' && c.status === 'permission_denied')
          ? 'connector_permission_denied_firewall_rules'
          : 'connector_' + c.status;
        if(key === 'os_counters' && c.status === 'not_configured'){
          osCountersBannerTip = osCountersHint();
        }
        connectorLines.push(label + ': ' + translateError(errorKey));
      }
    });
  }
  // A-38: `network_profile` is a top-level key (not folded into
  // `connectors` above — see security_console.py._perimeter_payload's own
  // docstring for why), so it needs this one explicit check rather than
  // the generic loop above picking it up automatically.
  if(lastConsoleData.network_profile && lastConsoleData.network_profile.connector
     && lastConsoleData.network_profile.connector.status !== 'ok'){
    connectorLines.push(
      (TOOL_LABELS.network_profile || 'network_profile') + ': ' +
      translateError('connector_' + lastConsoleData.network_profile.connector.status)
    );
  }
  // A-42: `allowlist` is a top-level key on `ids` only (security_console.py.
  // _ids_payload), same "own nested connector, not folded into the generic
  // `connectors` loop" shape as `network_profile` above. Reuses A-29's
  // `crowdsec_*` error vocabulary (not the generic `connector_*` one) since
  // this is driven by the SAME machine-level credential gap
  // `crowdsec_write_not_configured`/`crowdsec_unreachable`/
  // `crowdsec_unauthorized` already describe for ban/unban — reusing it
  // here avoids a confusing second, differently-worded message for what is
  // the exact same underlying "no machine-level login configured" state.
  if(lastConsoleData.allowlist && lastConsoleData.allowlist.connector
     && lastConsoleData.allowlist.connector.status !== 'ok'){
    var allowlistStatus = lastConsoleData.allowlist.connector.status;
    var allowlistErrKey = allowlistStatus === 'not_configured'
      ? 'crowdsec_write_not_configured'
      : 'crowdsec_' + allowlistStatus;
    connectorLines.push((TOOL_LABELS.allowlist || 'allowlist') + ': ' + translateError(allowlistErrKey));
  }
  if(connectorLines.length){
    connErrBox.textContent = connectorLines.join(' · ');
    connErrBox.title = osCountersBannerTip || '';
    connErrBox.hidden = false;
  } else {
    connErrBox.title = '';
    connErrBox.hidden = true;
  }

  var powerBtn = document.getElementById('conPower');
  var enabled = !!lastConsoleData.enabled;
  powerBtn.classList.toggle('off', !enabled);
  powerBtn.disabled = false;
  powerBtn.textContent = enabled ? (lang === 'ru' ? 'Включено' : 'Enabled') : (lang === 'ru' ? 'Выключено' : 'Disabled');

  // Замечание пользователя (2026-07-31): заголовок раздела может быть
  // переопределён консолью (CONSOLE_META.<id>.metricsSectionTitle) — если
  // консоль его не задаёт, остаётся исходный текст из index.html
  // (data-ru/data-en на самом элементе, уже применённый applyLang()).
  var metricsTitleEl = document.getElementById('conMetricsTitle');
  if(metricsTitleEl){
    metricsTitleEl.textContent = meta.metricsSectionTitle
      ? meta.metricsSectionTitle[lang]
      : metricsTitleEl.dataset[lang];
  }

  var metricsBox = document.getElementById('conMetrics');
  metricsBox.innerHTML = '';
  // Замечание пользователя (2026-07-31): «сузить их всех, чтобы в одну
  // строку влезали» — раньше .kb-stats всегда было ровно 4 колонки
  // (styles.css), независимо от того, сколько плиток консоль реально
  // показывает; у perimeter теперь 6. Число колонок — по фактическому
  // числу плиток ЭТОЙ консоли (общее для всех консолей, не только
  // perimeter, за счёт --kb-n — см. .kb-stats в styles.css), так что
  // каждая консоль всегда помещается в один ряд, а не 4 фиксированных
  // слота с пустым местом или переполнением.
  metricsBox.style.setProperty('--kb-n', Object.keys(meta.metricLabels).length);
  var metrics = lastConsoleData.metrics || {};
  Object.keys(meta.metricLabels).forEach(function(key){
    var tile = document.createElement('div');
    tile.className = 'kbstat';
    var labelMeta = meta.metricLabels[key];
    // Замечание пользователя (2026-07-31): необязательная подсветка
    // плитки по СМЫСЛУ значения (не по самому факту наличия числа) —
    // `tileVariant(value)` возвращает 'good'/'bad'/'muted' или null/
    // undefined (без подсветки, как раньше). Определяется вместе с самой
    // метрикой (тот же принцип, что и `values`/`tipRu` выше — правило
    // живёт рядом с метрикой, которую описывает, а не размазано по общему
    // циклу рендера консолей).
    if(typeof labelMeta.tileVariant === 'function'){
      var variant = labelMeta.tileVariant(metrics[key]);
      if(variant) tile.classList.add('kbstat-' + variant);
    }
    // A-23: an optional per-metric tooltip (tipRu/tipEn) — same field names
    // already used for `actions[].tipRu/tipEn` above. Set on the whole tile
    // (not just the label) so hovering the number itself also explains it —
    // the number-with-no-explanation was exactly the original complaint.
    var tip = lang === 'ru' ? labelMeta.tipRu : labelMeta.tipEn;
    if(tip) tile.title = tip;
    var n = document.createElement('span');
    n.className = 'kbstat-n';
    n.textContent = key.indexOf('_at') !== -1 ? formatTimestamp(metrics[key]) : formatValue(metrics[key]);
    var l = document.createElement('div');
    l.className = 'kbstat-l';
    l.textContent = labelMeta[lang];
    tile.appendChild(n);
    tile.appendChild(l);
    metricsBox.appendChild(tile);
  });

  // A-32: `ids`'s `metrics.active_bans_local` is already honestly computed
  // and labelled (A-23) — the problem was never the number itself, it was
  // that a real, good "0" sits right next to `active_bans_community`'s much
  // bigger, unrelated global count with no visual contrast, so a user reads
  // "everything's empty/broken" instead of "no real attacks here". This
  // banner is the missing contrast: an explicit, visually distinct verdict
  // above the metric tiles, positive when the honest count is 0, a plain
  // factual (not alarmist — principle 10, "не выдумывать тревожность")
  // warning when it's not. Hidden on every console other than `ids`, and
  // hidden on `ids` itself too if `active_bans_local` is `None` (connector
  // not configured/unreachable — see crowdsec.py's fetch_ids_console_data
  // docstring) since claiming "no attacks" would be fabricating an all-
  // clear the data doesn't actually support.
  //
  // Task brief scopes A-32 to this file alone (no index.html/styles.css
  // changes), so the banner element is created here at runtime — once,
  // then reused on every later renderConsole() call — rather than added as
  // static markup + new CSS classes. Its colours reference the SAME CSS
  // custom properties every other status pill in this app already reads
  // (--good-soft/--good-t/--warn-soft/--warn-t — see styles.css's :root and
  // e.g. .sec-state.ok/.degraded), so it stays visually consistent with the
  // rest of the panel (and with the CSS-driven light/dark theme) without
  // inventing a new hardcoded colour.
  var idsStatusBox = document.getElementById('conIdsStatus');
  if(!idsStatusBox){
    idsStatusBox = document.createElement('div');
    idsStatusBox.id = 'conIdsStatus';
    idsStatusBox.style.borderRadius = '8px';
    idsStatusBox.style.padding = '9px 12px';
    idsStatusBox.style.fontSize = '12.5px';
    idsStatusBox.style.fontWeight = '600';
    idsStatusBox.style.marginBottom = '14px';
    idsStatusBox.hidden = true;
    metricsBox.parentNode.insertBefore(idsStatusBox, metricsBox);
  }
  var localBans = lastConsoleId === 'ids' ? metrics.active_bans_local : null;
  if(typeof localBans === 'number'){
    idsStatusBox.hidden = false;
    if(localBans === 0){
      idsStatusBox.style.background = 'var(--good-soft)';
      idsStatusBox.style.color = 'var(--good-t)';
      // A-26: phrase the (honest) "no history" case differently from the
      // "real 7-day chart" case rather than inventing a period the data
      // doesn't back — `chart.values` is this same metric's real daily
      // history (services/metrics/chart.py), empty exactly when there
      // isn't enough of it yet (fresh install / CrowdSec just configured).
      var idsChartValues = (lastConsoleData.chart && lastConsoleData.chart.values) || [];
      if(idsChartValues.length){
        idsStatusBox.textContent = lang === 'ru'
          ? '✅ Реальных атак на эту машину не обнаружено за последние 7 дней'
          : '✅ No real attacks detected on this machine over the last 7 days';
      } else {
        idsStatusBox.textContent = lang === 'ru'
          ? '✅ Реальных атак на эту машину не обнаружено на данный момент'
          : '✅ No real attacks detected on this machine at this time';
      }
    } else {
      idsStatusBox.style.background = 'var(--warn-soft)';
      idsStatusBox.style.color = 'var(--warn-t)';
      idsStatusBox.textContent = lang === 'ru'
        ? '⚠️ Зафиксировано реальных попыток на этой машине: ' + localBans
        : '⚠️ Real attempts detected on this machine: ' + localBans;
    }
  } else {
    idsStatusBox.hidden = true;
  }

  // Замечание пользователя (2026-08-02): тот же принцип, что и у A-32's
  // idsStatusBox выше — явный, визуально контрастный вердикт над плитками
  // метрик на `av`, а не только цвет самих плиток. Два независимых
  // честных сигнала, могут быть оба сразу (джойнятся текстом, красный
  // стиль побеждает — активная угроза важнее просроченной проверки):
  //   - «Защита под угрозой»: последняя проверка просрочена (>3 дней) ИЛИ
  //     базы сигнатур устарели (>1 дня) — те же пороги, что и у
  //     CONSOLE_META.av.metricLabels' tileVariant выше, не отдельные числа.
  //   - «Угроза заражения»: в карантине есть хотя бы одна запись.
  var avStatusBox = document.getElementById('conAvStatus');
  if(!avStatusBox){
    avStatusBox = document.createElement('div');
    avStatusBox.id = 'conAvStatus';
    avStatusBox.style.borderRadius = '8px';
    avStatusBox.style.padding = '9px 12px';
    avStatusBox.style.fontSize = '12.5px';
    avStatusBox.style.fontWeight = '600';
    avStatusBox.style.marginBottom = '14px';
    avStatusBox.hidden = true;
    metricsBox.parentNode.insertBefore(avStatusBox, metricsBox);
  }
  if(lastConsoleId === 'av'){
    var avMessages = [];
    var quarantineCount = metrics.quarantine_count;
    var hasQuarantineThreat = typeof quarantineCount === 'number' && quarantineCount > 0;
    if(hasQuarantineThreat){
      avMessages.push(lang === 'ru'
        ? '🦠 Угроза заражения: в карантине ' + quarantineCount
        : '🦠 Infection threat: ' + quarantineCount + ' item(s) in quarantine');
    }
    var lastScanDays = daysSinceIso(metrics.last_scan_at);
    var dbDays = daysSinceIso(metrics.databases_updated_at);
    // Реальный баг, найден пользователем живьём (2026-08-16, см.
    // CONSOLE_META.av.metricLabels.last_scan_at's tileVariant выше для той
    // же правки): «ни разу не проверялось»/«ни разу не обновлялось»
    // (days === null) раньше не считалось риском — плитка «Последняя
    // проверка» после фикса стала красной, а этот баннер прямо над ней
    // всё равно писал «✅ проверки и базы актуальны», явное противоречие.
    var protectionAtRisk = (lastScanDays === null || lastScanDays > 3) || (dbDays === null || dbDays > 1);
    if(protectionAtRisk){
      avMessages.push(lang === 'ru' ? '⚠️ Защита под угрозой' : '⚠️ Protection at risk');
    }
    if(avMessages.length){
      avStatusBox.hidden = false;
      avStatusBox.textContent = avMessages.join(' · ');
      if(hasQuarantineThreat){
        avStatusBox.style.background = 'var(--crit-soft)';
        avStatusBox.style.color = 'var(--crit-t)';
      } else {
        avStatusBox.style.background = 'var(--warn-soft)';
        avStatusBox.style.color = 'var(--warn-t)';
      }
    } else if(quarantineCount === 0){
      avStatusBox.hidden = false;
      avStatusBox.style.background = 'var(--good-soft)';
      avStatusBox.style.color = 'var(--good-t)';
      avStatusBox.textContent = lang === 'ru'
        ? '✅ Угроз не обнаружено, проверки и базы актуальны'
        : '✅ No threats found, scans and databases are up to date';
    } else {
      avStatusBox.hidden = true;
    }
  } else {
    avStatusBox.hidden = true;
  }

  // Chart (A-26): `chart.values` is now real last-7-days history for every
  // console (see services/metrics/ on the backend) — a uniform
  // {metric, unit, values} shape across all 6 consoles. An EMPTY `values`
  // is the honest, specific "недостаточно истории ещё" signal (fresh
  // install / a tool only just configured), deliberately NOT the old
  // "chart rendering not implemented" placeholder this replaces —
  // rendering IS implemented below (renderConsoleChart/drawBarChart).
  document.getElementById('conChartCard').hidden = false;
  document.getElementById('conChartTitle').textContent = meta.chartTitle[lang];
  renderConsoleChart(lastConsoleData.chart || {});

  // A-41: «Карта соединений» — only ever shown on `network` (its
  // `connections`/`connectors.geoip` fields do not exist on any other
  // console's payload), same visibility pattern as A-38's
  // perimeterNetworkSection/A-33's avScanHistorySection below.
  var mapCard = document.getElementById('conMapCard');
  if(lastConsoleId === 'network'){
    var geoipStatus = (lastConsoleData.connectors && lastConsoleData.connectors.geoip
      && lastConsoleData.connectors.geoip.status) || 'not_configured';
    renderConnectionsMap(
      lastConsoleData.connections || [],
      geoipStatus,
      (lastConsoleData.connector || {}).status
    );
  } else {
    mapCard.hidden = true;
  }

  var listSection = document.getElementById('conListSection');
  // A-35: hint box is generic (keyed off `meta.listHint`, not off
  // `lastConsoleId === 'logs'` directly) so it renders/hides the same way
  // regardless of which of the three branches below the current console
  // falls into — today only `logs` sets `listHint`, so this stays hidden
  // for every other console including `av`'s quarantine special-case.
  var hintBox = document.getElementById('conListHint');
  if(hintBox){
    if(meta.listHint){
      hintBox.textContent = meta.listHint[lang];
      hintBox.hidden = false;
    } else {
      hintBox.hidden = true;
    }
  }
  if(lastConsoleId === 'av'){
    // A-27: `av`'s list section is repurposed for the quarantine list —
    // populated on demand by the "Карантин" button (see
    // handleShowQuarantine), NOT from `meta.listKey`/`lastConsoleData`
    // like the other consoles below: `GET /consoles/av` itself never
    // returns quarantine file listings (that would mean an extra
    // directory read + metadata parse on every single console poll, most
    // of which never open the quarantine view at all) — a dedicated `GET
    // .../clamav/quarantine` call happens only when the operator actually
    // asks to see it.
    document.getElementById('conListTitle').textContent = lang === 'ru' ? 'Карантин' : 'Quarantine';
    if(avQuarantineVisible){
      listSection.hidden = false;
      renderQuarantineList(lastQuarantineItems || []);
    } else {
      listSection.hidden = true;
    }
  } else if(meta.listKey){
    listSection.hidden = false;
    document.getElementById('conListTitle').textContent = meta.listTitle[lang];
    renderConsoleList(lastConsoleData[meta.listKey] || []);
  } else {
    listSection.hidden = true;
  }

  // A-54: «Экспорт журнала» lives right next to the connections-list title
  // now, only for `network` — moved out of the generic «Управление» button
  // row (see CONSOLE_META.network's own A-54 comment above for why: the two
  // OTHER actions that used to sit next to it were dead placeholders and
  // got removed outright, which would have left `export_log` alone in an
  // otherwise-empty section). `logs` still exports via the generic
  // mechanism below (`ACTION_HANDLERS.export_log`) — it has two OTHER real
  // actions already, so its «Управление» section stays populated and
  // moving its button would serve no purpose.
  var listExportBtn = document.getElementById('conListExportBtn');
  listExportBtn.hidden = lastConsoleId !== 'network';

  // A-33: the persistent scan-history list — only ever shown on the `av`
  // console, hidden (and left untouched) on every other one, same
  // visibility pattern as the quarantine section above. Замечание
  // пользователя (2026-08-02): the sibling «Проверить папку» input+button
  // section this comment used to also cover moved into a modal (see
  // handleOpenCustomScanModal/avCustomScanModalOverlay) — no longer part
  // of this always-rendered section, so no element lookup for it here.
  var scanHistorySection = document.getElementById('avScanHistorySection');
  if(lastConsoleId === 'av'){
    scanHistorySection.hidden = false;
    renderScanHistoryList(lastScanHistoryItems || []);
  } else {
    scanHistorySection.hidden = true;
  }

  // Замечание пользователя (2026-07-23): «Правила фаервола» больше не
  // подменяет список открытых портов (conListSection выше всегда честно
  // показывает ports, см. ту же ветку рендера) — своя, независимая
  // секция, показывается/прячется по тому же perimeterRulesVisible
  // флагу, только для perimeter (тот же паттерн видимости, что и у
  // A-33's av-only блоков ниже).
  var firewallRulesSection = document.getElementById('perimeterFirewallRulesSection');
  if(lastConsoleId === 'perimeter' && perimeterRulesVisible){
    firewallRulesSection.hidden = false;
    renderFirewallRulesList(lastFirewallRules || []);
  } else {
    firewallRulesSection.hidden = true;
  }

  // A-45: «Проверить обновления»/«Применить обновления» — own independent
  // section, only for `ids`, same visibility-via-flag pattern as
  // perimeterFirewallRulesSection above (idsScenarioUpdatesVisible toggled
  // by handleCheckScenarioUpdates).
  var scenarioUpdatesSection = document.getElementById('idsScenarioUpdatesSection');
  if(lastConsoleId === 'ids' && idsScenarioUpdatesVisible){
    scenarioUpdatesSection.hidden = false;
    renderScenarioUpdatesSection();
  } else {
    scenarioUpdatesSection.hidden = true;
  }

  // A-38: «Текущая сеть» + «Известные сети» — both only ever shown on the
  // `perimeter` console, same visibility pattern as A-33's av-only blocks
  // above.
  var networkSection = document.getElementById('perimeterNetworkSection');
  var knownNetworksSection = document.getElementById('perimeterKnownNetworksSection');
  if(lastConsoleId === 'perimeter'){
    networkSection.hidden = false;
    knownNetworksSection.hidden = false;
    renderPerimeterNetworkProfile(lastConsoleData.network_profile || {});
    renderKnownNetworksList((lastConsoleData.network_profile && lastConsoleData.network_profile.known) || []);
  } else {
    networkSection.hidden = true;
    knownNetworksSection.hidden = true;
  }

  // A-54: a console with NO actions at all (currently only `network`, since
  // A-52/A-53 replaced its two dead placeholders with real per-connection
  // actions and its export button moved next to the list title above) gets
  // its whole «Управление» section hidden — an empty heading over an empty
  // button row is worse than no section, not a harmless default state.
  // General rule, not hardcoded to `network`: any future console that ships
  // with zero actions gets the same treatment automatically.
  var actionsEmpty = meta.actions.length === 0;
  document.getElementById('conActionsHeading').hidden = actionsEmpty;
  var actionsBox = document.getElementById('conActions');
  actionsBox.hidden = actionsEmpty;
  if(actionsEmpty) setConActionStatus(null);
  actionsBox.innerHTML = '';
  // A-55: when the backup connector is not configured (no restic / disabled /
  // no password / no repository — see wiring.py::backup_connector_status),
  // EVERY backup-console action — including the two with real handlers —
  // becomes an honest disabled with the machine reason as its tooltip,
  // instead of an enabled button that can only fail on click (GUI-прогон
  // 2026-09-19, находка F1). Other consoles have no `connector.reason`
  // concept yet and are untouched.
  var backupConnectorReason = (lastConsoleId === 'backup'
    && lastConsoleData.connector && lastConsoleData.connector.status !== 'ok')
    ? (lastConsoleData.connector.reason || 'connector_' + lastConsoleData.connector.status)
    : null;
  meta.actions.forEach(function(action){
    var btn = document.createElement('button');
    // A-36: `action.danger` (currently only perimeter's "Заблокировать все
    // входящие") gets its own alarming red style instead of the default
    // ghost button — a wide-blast-radius one-shot action deserves to look
    // different from every other, safely-reversible action button.
    btn.className = action.danger ? 'btn-danger' : 'btn-ghost';
    btn.type = 'button';
    btn.textContent = action[lang];
    // A-12: the backup console is the first one with a real tool behind
    // some of its actions (ACTION_HANDLERS below) — those get enabled with
    // a real onclick; every other action on every other console still has
    // no real tool yet (A-11), so it stays a disabled placeholder exactly
    // as before.
    var handler = action.id && ACTION_HANDLERS[action.id];
    if(backupConnectorReason){
      btn.disabled = true;
      btn.title = translateError(backupConnectorReason);
    } else if(handler){
      btn.disabled = false;
      // A-63-5 (owner feedback, live 2026-09-21): long elevated actions
      // (freshclam, cscli, netsh …) gave NO feedback while running — the
      // button just sat there and the operator could not tell click-fail
      // from "working". Wrap every real handler: while its promise runs,
      // the button shows a pulsating «Выполняется…» (or the action's own
      // more specific busyRu/busyEn wording) and is disabled against
      // double-clicks; the original label is restored when the promise
      // settles (or immediately for non-promise handlers).
      attachButtonBusyHandler(
        btn, handler,
        lang === 'ru' ? (action.busyRu || 'Выполняется…') : (action.busyEn || 'Working…')
      );
      // A-27/A-23 pattern: an enabled action can still carry an explanatory
      // tooltip (e.g. "Перечитать базы" clarifying it never fetches new
      // signatures from the internet) — same tipRu/tipEn fields the
      // disabled/`soon` branch below already uses, just not gated on being
      // disabled this time.
      if(action.tipRu || action.tipEn) btn.title = lang === 'ru' ? action.tipRu : action.tipEn;
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
    var settingMeta = meta.settingLabels[key];
    row.className = 'st-row';
    // A-42: an optional per-setting tooltip (same `tipRu`/`tipEn` field
    // names the metric tiles above already use) — e.g. `ids`'s
    // `rule_source` explaining it is this project's own configured
    // constant, not a value read from CrowdSec.
    var settingTip = lang === 'ru' ? settingMeta.tipRu : settingMeta.tipEn;
    if(settingTip) row.title = settingTip;
    var label = document.createElement('b');
    label.textContent = settingMeta[lang];
    row.appendChild(label);

    var value = settings[key];
    var val = document.createElement('span');
    // Замечание пользователя (2026-08-02): необязательный кастомный
    // форматтер (напр. av's `full_scan_schedule` — объект
    // {enabled,hour,minute}, не boolean/строка, ни одна из веток ниже его
    // не поймёт правильно) — проверяется первым, до всех остальных веток.
    if(typeof settingMeta.formatValue === 'function'){
      val.className = 'st-val';
      val.textContent = settingMeta.formatValue(value, lang);
    } else if(typeof value === 'boolean'){
      val.className = 'st-tgl' + (value ? ' on' : '');
      val.textContent = value ? (lang === 'ru' ? 'включено' : 'on') : (lang === 'ru' ? 'выключено' : 'off');
    } else if(settingMeta.values && settingMeta.values[value]){
      // A-42: a machine-readable sentinel value (e.g. `ids`'s
      // `ban_policy: "per_scenario"`) translated via this setting's own
      // `values` lookup — the server never sends RU/EN text itself
      // (CLAUDE.md's localisation rule), only this code. `st-val-wrap`
      // (styles.css) lets this run to a real explanatory sentence instead
      // of `.st-val`'s default single-line `nowrap` (correct for every
      // other, short setting value) silently clipping it.
      val.className = 'st-val st-val-wrap';
      val.textContent = settingMeta.values[value][lang];
    } else {
      val.className = 'st-val';
      val.textContent = formatValue(value).replace(/_/g, ' ');
    }
    row.appendChild(val);
    // Замечание пользователя (2026-08-02): необязательная кликабельность
    // (напр. av's «Расписание полной проверки» — реально открывает
    // модалку редактирования, не просто текст) — визуальная подсказка
    // (курсор + шеврон), не просто скрытый onclick.
    if(typeof settingMeta.onClick === 'function'){
      row.classList.add('st-row-clickable');
      row.onclick = settingMeta.onClick;
      var chevron = document.createElement('span');
      chevron.className = 'st-row-chevron';
      chevron.textContent = '›';
      chevron.setAttribute('aria-hidden', 'true');
      row.appendChild(chevron);
    }
    settingsBox.appendChild(row);
  });

  // A-42: «Белый список» — real CrowdSec allowlist entries (security_console.py.
  // _ids_payload's `allowlist` key), only ever shown on the `ids` console,
  // same visibility pattern as A-38's perimeter-only sections above.
  var allowlistSection = document.getElementById('idsAllowlistSection');
  if(allowlistSection){
    if(lastConsoleId === 'ids'){
      allowlistSection.hidden = false;
      renderIdsAllowlist(lastConsoleData.allowlist || {});
    } else {
      allowlistSection.hidden = true;
    }
  }
}

/* A-26: chart rendering — plain <canvas> 2D drawing, NO charting library
   (project convention "минимум зависимостей", see CLAUDE.md's license/
   dependency gate). `chart` is the backend's uniform
   {metric, unit, values} shape (see routers/security_console.py's payload
   functions + services/metrics/chart.py) — `values` is either `[]`
   ("недостаточно истории ещё" — a fresh install, or a tool only just
   configured, honestly distinct from the old, now-removed "chart not
   implemented" placeholder) or a real list of exactly 7 daily points,
   oldest first. */
function renderConsoleChart(chart){
  var emptyBox = document.getElementById('conChartEmpty');
  var canvas = document.getElementById('conChartCanvas');
  var legend = document.getElementById('conChartLegend');
  var lang = currentLang();

  // Замечание пользователя (2026-07-31): раньше «Активные баны CrowdSec»
  // была ОДНОЙ суммой local+community в одном столбике — читалось как
  // «столько всего произошло на этой машине», хотя почти всегда это
  // мировой community-блоклист CrowdSec, не реальная активность именно
  // здесь (тот же класс путаницы, что A-23 уже чинила для плиток метрик
  // ids). `perimeter`'s chart теперь единственный источник с ДВУМЯ
  // сериями (`values_community`/`values_local`, security_console.py's
  // _perimeter_payload) — остальные консоли (av/ids/network/logs/backup)
  // не тронуты, у них по-прежнему один `chart.values`.
  if(chart && (chart.values_community || chart.values_local)){
    var community = chart.values_community || [];
    var local = chart.values_local || [];
    // Пусто целиком, только если ОБЕ серии ещё не накопили историю —
    // если хотя бы одна уже реальна, честнее показать график сейчас
    // (`active_bans_local` уже давно копится через консоль ids), чем
    // прятать уже готовые данные на 2 дня ради вновь заведённой
    // `active_bans_community`, которая просто ещё не успела накопиться.
    if(!community.length && !local.length){
      emptyBox.hidden = false;
      canvas.hidden = true;
      if(legend) legend.hidden = true;
      return;
    }
    emptyBox.hidden = true;
    canvas.hidden = false;
    if(legend){
      legend.hidden = false;
      document.getElementById('conChartLegendA').textContent =
        lang === 'ru' ? 'Локальные (эта машина)' : 'Local (this machine)';
      document.getElementById('conChartLegendB').textContent =
        lang === 'ru' ? 'Мировой список CrowdSec' : 'CrowdSec worldwide list';
    }
    drawGroupedBarChart(canvas, local, community);
    return;
  }

  if(legend) legend.hidden = true;
  var values = (chart && chart.values) || [];
  if(!values.length){
    emptyBox.hidden = false;
    canvas.hidden = true;
    return;
  }
  emptyBox.hidden = true;
  canvas.hidden = false;
  drawBarChart(canvas, values);
}

// Minimal, dependency-free daily bar chart: `values.length` bars (up to 7),
// tallest bar scaled to the canvas height, oldest-first left-to-right
// (today is the rightmost bar) — a trend-at-a-glance sparkline, not an
// analytical instrument (no axes/gridlines/tooltips, matching the
// "простой" requirement this task was scoped to).
function drawBarChart(canvas, values){
  var dpr = window.devicePixelRatio || 1;
  var cssWidth = canvas.clientWidth || 320;
  var cssHeight = canvas.clientHeight || 120;
  canvas.width = Math.round(cssWidth * dpr);
  canvas.height = Math.round(cssHeight * dpr);

  var ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  var styles = getComputedStyle(document.documentElement);
  var barColor = (styles.getPropertyValue('--accent') || '#0E7A6E').trim() || '#0E7A6E';
  var baseColor = (styles.getPropertyValue('--line') || '#E3E7EC').trim() || '#E3E7EC';

  var pad = 8;
  var baselineY = cssHeight - pad;
  ctx.strokeStyle = baseColor;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, baselineY + 0.5);
  ctx.lineTo(cssWidth - pad, baselineY + 0.5);
  ctx.stroke();

  var max = 0;
  for(var i = 0; i < values.length; i++){ if(values[i] > max) max = values[i]; }

  var innerW = cssWidth - pad * 2;
  var innerH = cssHeight - pad * 2 - 4; // small headroom above the tallest bar
  var n = values.length;
  var gap = 6;
  var barW = Math.max((innerW - gap * (n - 1)) / n, 2);

  ctx.fillStyle = barColor;
  for(var j = 0; j < n; j++){
    var v = values[j];
    var barH = max > 0 ? (v / max) * innerH : 0;
    if(v > 0 && barH < 2) barH = 2; // a real non-zero day must stay visible, not round away to nothing
    var x = pad + j * (barW + gap);
    var y = baselineY - barH;
    ctx.fillRect(x, y, barW, barH);
  }

  // Accessible fallback / hover context — canvas has no native per-bar
  // tooltip without a lot more code, so a single summary title is the
  // "простой" (simple) compromise for this task.
  canvas.setAttribute('aria-label', values.join(', '));
  canvas.title = values.join(', ');
}

// Замечание пользователя (2026-07-31): «Активные баны CrowdSec» на «Защите
// периметра» — та же однобарная drawBarChart выше, но с ДВУМЯ значениями
// в день (местные/мировые) вместо одного — местные (`--accent`, важный
// сигнал) и мировые (`--muted`, большой, но не про эту машину, тот же
// смысловой контраст, что и на консоли ids). Обе серии дополняются нулями
// до 7 точек независимо, если одна короче другой (см. renderConsoleChart) —
// временный честный компромисс на случай, когда одна серия ещё копит
// историю, а другая уже готова.
function drawGroupedBarChart(canvas, seriesLocal, seriesCommunity){
  var dpr = window.devicePixelRatio || 1;
  var cssWidth = canvas.clientWidth || 320;
  var cssHeight = canvas.clientHeight || 120;
  canvas.width = Math.round(cssWidth * dpr);
  canvas.height = Math.round(cssHeight * dpr);

  var ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  var styles = getComputedStyle(document.documentElement);
  var localColor = (styles.getPropertyValue('--accent') || '#0E7A6E').trim() || '#0E7A6E';
  var communityColor = (styles.getPropertyValue('--muted') || '#828E9C').trim() || '#828E9C';
  var baseColor = (styles.getPropertyValue('--line') || '#E3E7EC').trim() || '#E3E7EC';

  var n = Math.max(seriesLocal.length, seriesCommunity.length, 1);
  function padded(series){
    var out = series.slice();
    while(out.length < n) out.unshift(0);
    return out;
  }
  var local = padded(seriesLocal);
  var community = padded(seriesCommunity);

  var pad = 8;
  var baselineY = cssHeight - pad;
  ctx.strokeStyle = baseColor;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, baselineY + 0.5);
  ctx.lineTo(cssWidth - pad, baselineY + 0.5);
  ctx.stroke();

  var max = 0;
  for(var i = 0; i < n; i++){
    if(local[i] > max) max = local[i];
    if(community[i] > max) max = community[i];
  }

  var innerW = cssWidth - pad * 2;
  var innerH = cssHeight - pad * 2 - 4;
  var groupGap = 6;
  var barGap = 2;
  var groupW = Math.max((innerW - groupGap * (n - 1)) / n, 4);
  var barW = Math.max((groupW - barGap) / 2, 1);

  for(var j = 0; j < n; j++){
    var groupX = pad + j * (groupW + groupGap);

    var localH = max > 0 ? (local[j] / max) * innerH : 0;
    if(local[j] > 0 && localH < 2) localH = 2;
    ctx.fillStyle = localColor;
    ctx.fillRect(groupX, baselineY - localH, barW, localH);

    var communityH = max > 0 ? (community[j] / max) * innerH : 0;
    if(community[j] > 0 && communityH < 2) communityH = 2;
    ctx.fillStyle = communityColor;
    ctx.fillRect(groupX + barW + barGap, baselineY - communityH, barW, communityH);
  }

  canvas.setAttribute(
    'aria-label',
    'local: ' + local.join(', ') + '; community: ' + community.join(', ')
  );
  canvas.title = 'local: ' + local.join(', ') + ' · community: ' + community.join(', ');
}

/* A-41: «Карта соединений» — the `network` console's overview visualization
   of WHERE its current connections' countries roughly are, at a glance.
   Same "plain <canvas>, no library" convention `drawBarChart` above already
   established (A-26), applied to a small equirectangular (lat/lon -> x/y)
   world projection instead of a bar chart.

   CATEGORICALLY NO network request of any kind happens anywhere in this
   whole block — no tile image fetch, no external stylesheet/font, nothing.
   This is not an incidental property; it is the entire reason A-41 exists
   (see docs/план-спецификация-фаза-0-карта-соединений-2026-07-23.md's
   "Важное архитектурное решение": a real Leaflet/Mapbox/Google-Maps map
   would fetch map TILES from an external server on every pan/zoom/render,
   handing that server the user's IP and the fact that a security product
   monitoring their connections is running — a direct regression of this
   whole product's "приватно, локально" principle, CLAUDE.md). Instead:
     - the land/continent outline (A-49, `world_land_outline.js`) is a
       STATIC local asset loaded once with the page (same `<script>`
       mechanism as this very file), never fetched per-render/pan/zoom —
       the guarantee above is about EXTERNAL, THIRD-PARTY tile servers
       specifically, not "zero bytes of map data ever" (see
       docs/план-спецификация-фаза-0-контур-карты-2026-08-16.md's own
       "Гарантия A-41... не нарушается" section for why this distinction
       is deliberate, not a quiet walk-back of the original decision);
     - each country "dot" is a `country_centroids.py`-supplied (lat, lon)
       (security_console.py's `_enrich_connections`, A-41) — a small,
       hand-written table of PUBLIC, FACTUAL coordinates (not a licensed
       dataset, not fetched at runtime — see that module's own licence-gate
       reasoning), never a live geocoding API call;
     - flag glyphs (`countryFlagEmoji()` below, A-40) are Unicode code
       points rendered by the OS/browser's own installed font, not an
       image asset fetched from anywhere.
   A live Playwright network-request interception is part of this task's own
   DoD specifically because this guarantee is the point of the feature, not
   an incidental detail — see the A-41 task report for that verification,
   re-confirmed for A-49's own addition (a static local asset changes
   nothing about the interception result — see that task's own report). */

// Pure equirectangular projection: (lat, lon) in decimal degrees -> a pixel
// position inside a `width` x `height` canvas area. Deliberately a free
// function with no canvas/DOM dependency at all (unlike drawConnectionsMap
// below) — the A-41 test suite's regression test drives this exact function
// directly (via Node's `vm` module against the real, unmodified app.js, the
// same technique test_a34_network_table_regression.py already established)
// to pin the projection formula itself without needing a real <canvas>.
function projectLatLon(lat, lon, width, height){
  return {
    x: (lon + 180) / 360 * width,
    y: (90 - lat) / 180 * height,
  };
}

// `drawConnectionsMap()`'s own mousemove hit-test (handleConMapMouseMove
// below) reads these two module-level vars rather than a closure, because —
// same reasoning as every other interactive element in this file — the
// canvas's own inline `onmousemove` HTML attribute (index.html) calls a
// plain top-level function by name; there is no addEventListener-based
// closure anywhere else in this file to attach one here either (see the two
// exceptions at the very bottom of this file, both intentionally global:
// `keydown`/`DOMContentLoaded`).
var lastMapPoints = [];
var lastMapSummaryTitle = '';

// A-63-3 (live full-stack finding, 2026-09-21): the LAST connections array
// that actually produced visible map points. The network console's 5s poll
// can legitimately come back with a HONEST empty payload (connector
// `unreachable` — e.g. a slow osqueryi scan timing out) and re-rendering
// the map from it used to wipe every dot off the map — the owner's «клик по
// узлу — и всё исчезло с карты» turned out to be this background
// re-render, not the click itself (the canvas has NO click handler at all,
// only mousemove/mouseleave — see index.html). Keeping the last good
// snapshot lets renderConnectionsMap keep the picture on screen (clearly
// labelled as such) until a real payload arrives.
var lastGoodMapConnections = [];

// `connections` (the SAME enriched rows renderConsoleList already reads,
// see security_console.py._enrich_connections) -> one entry per DISTINCT
// `country` among rows that actually have a resolved (lat, lon) — never one
// entry per raw connection: many connections to the same cloud provider's
// IP range would otherwise all resolve to the exact same country centroid
// and stack invisibly on top of each other (the A-41 plan's own explicit
// reasoning for "one point per country, not per connection"). A row with no
// resolved country (or a resolved country this build's small centroid table
// does not carry, see country_centroids.py's own honest-`None` docstring)
// contributes no point at all — the honest degradation the A-41 plan calls
// for, not a fabricated placeholder location.
function groupConnectionsByCountry(connections){
  var byCountry = {};
  var order = [];
  (connections || []).forEach(function(item){
    if(!item || item.lat === null || item.lat === undefined || item.lon === null || item.lon === undefined){
      return;
    }
    var code = item.country;
    if(!byCountry[code]){
      byCountry[code] = { country: code, lat: item.lat, lon: item.lon, count: 0, suspicious: false };
      order.push(code);
    }
    byCountry[code].count += 1;
    // A-40's own three-state `is_suspicious` (true/false/null) — only a
    // real `true` on ANY connection in this country's group marks the
    // whole dot suspicious; `null` (CrowdSec not checked) must never read
    // as "checked and suspicious" any more than it does in the table.
    if(item.is_suspicious === true) byCountry[code].suspicious = true;
  });
  return order.map(function(code){ return byCountry[code]; });
}

// Draws the land outline + home anchor + one dot per `groupConnectionsByCountry()`
// entry onto `canvas`, and (re)populates `lastMapPoints`/
// `lastMapSummaryTitle` for the mousemove hit-test below. Called on every
// `renderConsole()` for the `network` console (including A-39's live
// auto-refresh poll), same "re-drawn from scratch every time, no persistent
// canvas state" approach `drawBarChart` already uses.
function drawConnectionsMap(canvas, connections, lang){
  var dpr = window.devicePixelRatio || 1;
  var cssWidth = canvas.clientWidth || 320;
  var cssHeight = canvas.clientHeight || 220;
  canvas.width = Math.round(cssWidth * dpr);
  canvas.height = Math.round(cssHeight * dpr);

  var ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  var styles = getComputedStyle(document.documentElement);
  var lineColor = (styles.getPropertyValue('--line') || '#E3E7EC').trim() || '#E3E7EC';
  var accentColor = (styles.getPropertyValue('--accent') || '#0E7A6E').trim() || '#0E7A6E';
  var critColor = (styles.getPropertyValue('--crit') || '#CB463E').trim() || '#CB463E';
  var mutedColor = (styles.getPropertyValue('--muted') || '#828E9C').trim() || '#828E9C';
  var inkColor = (styles.getPropertyValue('--ink2') || '#5A6572').trim() || '#5A6572';
  var landColor = (styles.getPropertyValue('--surface3') || '#EEF1F4').trim() || '#EEF1F4';

  // A-49: real land/continent outline (world_land_outline.js, loaded as a
  // plain global before this file — see that file's own header for
  // source/licence) replaces the earlier coordinate-grid stand-in this
  // comment used to describe. Every ring projected through the SAME
  // projectLatLon() the rest of this function already uses for points —
  // one flat array of already-closed rings, GeoJSON's own exterior/hole
  // winding order fills correctly under canvas's default nonzero rule, no
  // separate polygon/hole grouping needed (verified live — this dataset
  // has exactly one hole ring, e.g. an inland sea, out of 126 total).
  if(typeof WORLD_LAND_OUTLINE !== 'undefined'){
    ctx.fillStyle = landColor;
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 1;
    WORLD_LAND_OUTLINE.forEach(function(ring){
      ctx.beginPath();
      ring.forEach(function(point, i){
        var p = projectLatLon(point[1], point[0], cssWidth, cssHeight);
        if(i === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      });
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    });
  }

  // "Home" anchor — a FIXED on-canvas position, deliberately NOT a real
  // geolocation of this machine (the A-41 plan is explicit this feature
  // must not attempt that at all — honestly labelled via this point's own
  // title text below, not a claimed real location). Originally bottom-
  // centre — harmless against the old grid-only backdrop, but a real bug
  // found live (2026-08-16, right after A-49 added the real land outline):
  // that fixed pixel position happens to sit on Antarctica once real
  // coastlines are visible, misleadingly implying that as this machine's
  // actual location. Moved to dead-centre (lat 0, lon 0), then — A-50
  // (2026-08-17), after the map grew taller — nudged a little further
  // south (~27°S, mid South Atlantic, nowhere near any coastline in this
  // outline, live-verified) so it reads more clearly as "open ocean, on
  // purpose" rather than sitting exactly on the equator/prime-meridian
  // crosshair. Same "position genuinely doesn't matter, just be honest
  // about it" reasoning the A-41 plan itself already stated.
  var home = { x: cssWidth / 2, y: cssHeight * 0.6 };
  var points = groupConnectionsByCountry(connections);

  // Home -> each country point: thin, translucent lines, drawn BEFORE the
  // dots so the dots visually sit on top of their own line.
  ctx.strokeStyle = accentColor;
  ctx.globalAlpha = 0.35;
  ctx.lineWidth = 1;
  points.forEach(function(point){
    var p = projectLatLon(point.lat, point.lon, cssWidth, cssHeight);
    ctx.beginPath(); ctx.moveTo(home.x, home.y); ctx.lineTo(p.x, p.y); ctx.stroke();
  });
  ctx.globalAlpha = 1;

  // The home marker itself — a laptop glyph (this project's own target
  // device, CLAUDE.md's "ноутбук"), not a plain dot: a user request
  // (2026-08-16) after the A-49 outline landed — even centred in open
  // ocean, a same-shaped circle still looked like just another connection
  // point at a glance. Same "Unicode code point rendered by the OS/
  // browser's own installed font, no image asset" convention this file's
  // own `countryFlagEmoji()` already established for flags below.
  ctx.fillStyle = inkColor;
  ctx.font = '15px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('💻', home.x, home.y);
  // Reset back to the canvas default alignment the country-label loop
  // below relies on (it never sets these itself) — state set on a shared
  // 2D context otherwise leaks into unrelated later fillText() calls.
  ctx.textAlign = 'start';
  ctx.textBaseline = 'alphabetic';

  var placed = [];
  points.forEach(function(point){
    var p = projectLatLon(point.lat, point.lon, cssWidth, cssHeight);
    // Radius grows with connection count (sqrt, not linear — one country
    // with 50 connections should not visually swallow the whole map) —
    // capped so a very chatty single remote host still stays a dot, not a
    // blob covering half the canvas.
    var radius = Math.min(4 + Math.sqrt(point.count) * 2.5, 14);
    // Same red accent A-40's own "Подозрительный узел" table badge already
    // uses (styles.css's --crit) — one visual language for "suspicious",
    // not a second one invented here.
    ctx.fillStyle = point.suspicious ? critColor : accentColor;
    ctx.beginPath(); ctx.arc(p.x, p.y, radius, 0, Math.PI * 2); ctx.fill();

    ctx.fillStyle = inkColor;
    ctx.font = '10px sans-serif';
    var flag = countryFlagEmoji(point.country);
    ctx.fillText((flag ? flag + ' ' : '') + point.country, p.x + radius + 3, p.y + 3);

    placed.push({
      x: p.x, y: p.y, radius: radius,
      country: point.country, count: point.count, suspicious: point.suspicious,
    });
  });

  lastMapPoints = placed;

  // Accessible fallback / default hover state — same "always-set canvas.title
  // as a summary" idea `drawBarChart` already established (A-26); the
  // mousemove hit-test below sharpens this into a precise per-point tooltip
  // while the cursor is actually over a dot, and falls back to this same
  // full-list summary everywhere else on the canvas (including the land
  // outline/home anchor, which is real and honest to describe too).
  var connectionsWord = lang === 'ru' ? 'соединений' : 'connections';
  var homeLabel = lang === 'ru' ? 'Локальный узел (это устройство)' : 'Local node (this device)';
  var summaryParts = points.map(function(point){
    return point.country + ' — ' + point.count + ' ' + connectionsWord;
  });
  var summary = homeLabel + (summaryParts.length ? ('; ' + summaryParts.join('; ')) : '');
  lastMapSummaryTitle = summary;
  canvas.title = summary;
  canvas.setAttribute('aria-label', summary);
}

// GeoIP-not-configured degradation + the actual draw call — called once per
// renderConsole() while `network` is the open console (see that function's
// own call site below). Deliberately NEVER hides the canvas itself (unlike
// renderConsoleChart's empty/canvas toggle above) — the land outline + home
// anchor are real and worth showing even with zero resolvable countries; only the
// explanatory note is conditional, so the map never reads as a mysteriously
// empty box with no explanation (the A-41 plan's own "не пустой холст без
// объяснения" requirement).
function renderConnectionsMap(connections, geoipStatus, connectorStatus){
  var card = document.getElementById('conMapCard');
  var canvas = document.getElementById('conMapCanvas');
  var noteBox = document.getElementById('conMapNote');
  var lang = currentLang();
  card.hidden = false;

  // A-63-3: remember the last payload that actually produced points, so a
  // subsequent honest-but-empty `unreachable` response (see the
  // lastGoodMapConnections docstring above) can still draw something real.
  if(geoipStatus === 'ok' && connections.length){
    lastGoodMapConnections = connections;
  }

  // A-63-3: an empty connections array is REAL data only when the connector
  // itself is healthy (no resolvable countries / genuinely no sockets).
  // When the connector is DOWN, the empty array means "we don't know" —
  // redrawing the map from it used to blank the whole picture for one poll
  // cycle (and the next poll usually restored it, producing the observed
  // "everything vanished from the map" flicker). In that case keep drawing
  // the last good snapshot and say so plainly in the note — the error
  // banner above already carries the connector's honest status.
  if(connectorStatus && connectorStatus !== 'ok' && !connections.length && lastGoodMapConnections.length){
    noteBox.hidden = false;
    noteBox.textContent = lang === 'ru'
      ? 'Источник данных соединений временно недоступен — карта показывает последнюю успешную выборку.'
      : 'The connections data source is temporarily unavailable — the map shows the last successful snapshot.';
    drawConnectionsMap(canvas, lastGoodMapConnections, lang);
    return;
  }

  if(geoipStatus !== 'ok'){
    noteBox.hidden = false;
    noteBox.textContent = lang === 'ru'
      ? 'GeoIP не настроен — карта показывает только контур и локальный узел, без стран соединений.'
      : 'GeoIP not configured — the map shows only the outline and the local node, no connection countries.';
  } else {
    noteBox.hidden = true;
  }

  drawConnectionsMap(canvas, connections, lang);
}

// Sharpens the map's default full-summary `canvas.title` (set unconditionally
// by drawConnectionsMap above) into a precise single-point tooltip while the
// cursor is actually over that point's dot — a plain distance check against
// `lastMapPoints` (populated by the most recent drawConnectionsMap call), no
// per-point DOM element at all (the A-41 plan's own "без DOM-элементов на
// каждую точку" requirement) and no canvas library hit-testing API needed.
function handleConMapMouseMove(event){
  var canvas = document.getElementById('conMapCanvas');
  if(!canvas || !lastMapPoints.length){ return; }
  var rect = canvas.getBoundingClientRect();
  var mx = event.clientX - rect.left;
  var my = event.clientY - rect.top;
  var lang = currentLang();
  for(var i = 0; i < lastMapPoints.length; i++){
    var point = lastMapPoints[i];
    var dx = mx - point.x;
    var dy = my - point.y;
    if(Math.sqrt(dx * dx + dy * dy) <= point.radius + 3){
      var connectionsWord = lang === 'ru' ? 'соединений' : 'connections';
      var suspiciousSuffix = point.suspicious
        ? (lang === 'ru' ? ' — подозрительно' : ' — suspicious')
        : '';
      canvas.title = point.country + ': ' + point.count + ' ' + connectionsWord + suspiciousSuffix;
      return;
    }
  }
  canvas.title = lastMapSummaryTitle;
}

function handleConMapMouseLeave(){
  var canvas = document.getElementById('conMapCanvas');
  if(canvas) canvas.title = lastMapSummaryTitle;
}

// A-34: `network`'s `connections` rows (see osquery.py's
// `fetch_network_console_data` — `protocol` arrives as osquery's raw numeric
// string, e.g. "6"/"17", not a name). Only the two protocols osquery's own
// `process_open_sockets` table actually ever reports on this stack are
// mapped to a name; anything else (a value neither of us has seen live) is
// shown as-is rather than silently swallowed or thrown on — same "never
// crash on an unexpected-but-real value" rule as `formatValue` below.
var NETWORK_PROTOCOL_LABELS = { '6': 'TCP', '17': 'UDP' };

// A-63-7 (live full-stack finding, 2026-09-21): the owner saw the bare
// «OS counters: не подключён» banner line and the generic "set connection
// parameters in .env" tooltip — both misleading on two counts. First,
// os_counters is NOT part of the «Стек защиты» bootstrap by DESIGN: it is
// not a service/container, there is nothing to deploy — the connector reads
// stock OS tools. Second, on Windows there is NO reliable non-admin
// per-process network byte counter at all (see traffic_counters.py's own
// docstring: every stock candidate was rejected with a reason; the real
// mechanism would need an elevated ETW trace) — so on the owner's own
// machine this source is honestly `not_configured` FOREVER, and no .env
// keys exist to change that. This hint says all of that plainly (RU/EN,
// Windows-aware via navigator) and backs both places the state shows: the
// console's error banner line and the «Отправлено/Получено» column header.
function osCountersHint(){
  var lang = currentLang();
  var isWindows = /win/i.test(navigator.platform || navigator.userAgent || '');
  if(lang === 'ru'){
    var baseRu = 'OS counters — это колонка «Отправлено/Получено»: сетевой трафик каждого процесса, посчитанный штатными средствами ОС. Это не сервис и не контейнер, поэтому его нет в «Стеке защиты» — разворачивать нечего.';
    if(isWindows){
      return baseRu + ' На Windows надёжного способа посчитать такой трафик без прав администратора нет, поэтому колонка честно показывает «—»; на macOS/Linux этот показатель работает из коробки.';
    }
    return baseRu + ' На этой ОС он работает из коробки; если вы видите этот баннер, штатный инструмент не найден или отказал.';
  }
  var baseEn = 'OS counters is the "Sent/Received" column: per-process network traffic counted with stock OS tools. It is not a service or a container, so it is absent from the Protection stack — there is nothing to deploy.';
  if(isWindows){
    return baseEn + ' Windows offers no reliable non-admin way to count this traffic, so the column honestly shows "—"; on macOS/Linux it works out of the box.';
  }
  return baseEn + ' On this OS it works out of the box; if you see this banner, the stock tool was not found or refused.';
}

function formatNetworkProtocol(protocol){
  if(protocol === null || protocol === undefined || protocol === '') return '—';
  return NETWORK_PROTOCOL_LABELS[protocol] || String(protocol);
}
// Renders "address:port", or just whichever half is actually present —
// `listening_ports` rows have no remote side at all, and either half can be
// individually null when osquery only partially resolves a socket.
function formatNetworkEndpoint(address, port){
  if((address === null || address === undefined) && port === null) return '—';
  if(address === null || address === undefined) return String(port);
  if(port === null || port === undefined) return address;
  return address + ':' + port;
}

// A-40: `connections[].country` is an ISO 3166-1 alpha-2 code (e.g. "US")
// or `null` (geoip.py's offline resolution — see that module's docstring
// for why a `null` here is honest, not a bug: no vendored database, or the
// address simply isn't a public range). Converts a 2-letter code into its
// Unicode flag emoji via the standard "regional indicator symbol" trick
// (each letter A-Z maps to one of 26 code points starting at U+1F1E6, and
// a flag emoji is just two of those side by side) — no image asset/library
// needed, works in every modern browser's font stack. Returns '' (not a
// placeholder glyph) for anything that isn't exactly 2 ASCII letters, so a
// future non-flag-shaped code (should not happen with real ISO data, but
// never trust external data unconditionally) degrades to just the bare
// code text via `formatNetworkCountry` below rather than a broken glyph.
function countryFlagEmoji(code){
  if(!code || code.length !== 2) return '';
  var upper = code.toUpperCase();
  var base = 0x1F1E6; // Regional Indicator Symbol Letter A
  var points = [];
  for(var i = 0; i < 2; i++){
    var letterIndex = upper.charCodeAt(i) - 65; // 'A' === 65
    if(letterIndex < 0 || letterIndex > 25) return '';
    points.push(base + letterIndex);
  }
  return String.fromCodePoint(points[0]) + String.fromCodePoint(points[1]);
}
function formatNetworkCountry(code){
  if(!code) return '—';
  var flag = countryFlagEmoji(code);
  return (flag ? flag + ' ' : '') + code.toUpperCase();
}

// A-35: `logs`'s `entries[].level` is a raw Wazuh/FIM keyword (today only
// ever `"notice"` in practice, see wazuh.py's `_finding_to_entry`) — showing
// that bare English word to a non-technical user reads as unexplained
// jargon, not a severity signal. This is a lookup, not a hardcoded 3-way
// branch, so a future connector/level this project hasn't seen yet
// (`warning`/`error`/`critical` are plausible from other FIM/log sources)
// degrades to the neutral tone instead of throwing or rendering blank —
// same "never fabricate, always degrade honestly" spirit as the rest of
// this file, just applied to an enum instead of a number.
var LOG_LEVEL_META = {
  notice: { ru: 'Обычное', en: 'Notice', tone: 'neutral' },
  info: { ru: 'Информация', en: 'Info', tone: 'neutral' },
  warning: { ru: 'Предупреждение', en: 'Warning', tone: 'warn' },
  error: { ru: 'Ошибка', en: 'Error', tone: 'crit' },
  critical: { ru: 'Критично', en: 'Critical', tone: 'crit' },
};
function describeLogLevel(level){
  var key = String(level || '').toLowerCase();
  return LOG_LEVEL_META[key] || { ru: level || '—', en: level || '—', tone: 'neutral' };
}

// A-35: same "truncate + full value in `title`" pattern already used by
// `drawBarChart`'s `canvas.title` above, applied to long FIM file paths
// (e.g. `/Users/<name>/Library/Application Support/Hranix Shield/assistant.db`)
// instead of a chart summary — short paths pass through unchanged, long
// ones collapse to "…/<parent dir>/<file name>" so the row stays readable,
// while the element's own `title` (set by the caller below) still carries
// the untouched full path for anyone who needs it.
function truncateFimPath(path, maxLen){
  maxLen = maxLen || 40;
  if(!path) return '';
  if(path.length <= maxLen) return path;
  var parts = path.split(/[\\/]+/).filter(function(p){ return p.length > 0; });
  var base = parts.pop() || path;
  var parent = parts.pop();
  var shortened = parent ? ('…/' + parent + '/' + base) : ('…/' + base);
  if(shortened.length > maxLen){
    // Even the parent+filename form is too long (e.g. one very long file
    // name) — hard-truncate from the front, keeping the (usually more
    // informative) tail, same "never silently show something misleading"
    // idea, just for a string instead of a number.
    shortened = '…' + shortened.slice(-(maxLen - 1));
  }
  return shortened;
}

function renderConsoleList(items){
  var box = document.getElementById('conList');
  box.innerHTML = '';
  // A-40: `network`'s table grew from 5 to 7 columns (Страна/Country,
  // Репутация/Reputation) — the shared `.con-list` box is capped at
  // max-width:760px (styles.css), sized for the OTHER 5 consoles' shorter
  // rows; without a wider variant here every network row would wrap onto a
  // second line, undermining the "readable table" point of this whole
  // branch. Reset to the plain class on every render (not just when
  // leaving `network`) so a stale wide box never lingers after switching
  // to a different console — same "explicit reset every render, never
  // assume the previous state" discipline the rest of this function
  // already applies to `box.innerHTML`.
  box.className = lastConsoleId === 'network' ? 'con-list con-list-wide' : 'con-list';
  if(!items || items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    // A-32: an empty `ids`'s `recent_attempts` is real good news (no local
    // intrusion attempts recorded), not "the panel has no data" — same
    // reasoning as the status banner in renderConsole() above. Every other
    // console's empty list (backup modules / network connections / log
    // entries) has no such positive meaning, so it keeps the generic text.
    if(lastConsoleId === 'ids'){
      empty.textContent = currentLang() === 'ru'
        ? '✅ Реальных попыток вторжения не зафиксировано — это хорошо'
        : "✅ No real intrusion attempts recorded — that's good";
    } else {
      empty.textContent = currentLang() === 'ru' ? 'Нет данных' : 'No data yet';
    }
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
  // A-29: `ids`'s `recent_attempts` rows now carry a real `id` (the
  // CrowdSec decision id — see crowdsec.py's `fetch_ids_console_data`
  // "A-29" docstring note) and are the wiring point for "Разбанить IP"
  // (see CONSOLE_META.ids.actions above for why that button is NOT a
  // generic action). Rendered as its own branch (like `backup` above)
  // rather than falling through to the generic key:value loop below, so
  // the raw numeric `id` isn't printed as if it were a metric, and so a
  // real "Разбанить" button can be attached to each row.
  if(lastConsoleId === 'ids'){
    items.forEach(function(item){
      var row = document.createElement('div');
      row.className = 'con-row';
      ['ip', 'vector', 'status'].forEach(function(key){
        var span = document.createElement('span');
        var k = document.createElement('span');
        k.className = 'cr-k';
        k.textContent = key + ': ';
        span.appendChild(k);
        span.appendChild(document.createTextNode(String(item[key])));
        row.appendChild(span);
      });
      var unbanBtn = document.createElement('button');
      unbanBtn.className = 'btn-ghost';
      unbanBtn.type = 'button';
      unbanBtn.style.marginLeft = 'auto';
      unbanBtn.textContent = lang === 'ru' ? 'Разбанить' : 'Unban';
      unbanBtn.disabled = item.id == null;
      unbanBtn.onclick = function(){ handleUnbanIp(item.id, item.ip, unbanBtn); };
      row.appendChild(unbanBtn);
      box.appendChild(row);
    });
    return;
  }
  // A-31: `perimeter`'s `ports` rows — the per-port process/pid/protocol
  // detail `metrics.open_ports` always summarized into a bare count (see
  // security_console.py._perimeter_payload / osquery.py's
  // fetch_listening_ports docstring). Rendered as its own branch (same
  // pattern as `ids`/`backup` above), not the generic key:value fallback
  // below, so "Порт"/"Процесс" get readable labels instead of a raw
  // `port: 8000` / `pid: 4242` dump, and protocol/process are combined into
  // one readable value each rather than four separate loose fields.
  // A-37: each row is now clickable — opens the port-detail modal
  // (openPortModal, see index.html's #portModalOverlay) with a
  // «Блокировать»/«Разблокировать» pair of real actions, plus a
  // `.port-blocked-badge` on rows the persistent `blocked_ports` table
  // (see security_console.py._perimeter_payload's A-37 addendum) already
  // marks `is_blocked: true`. `tabIndex`/`role`/`onkeydown` give the same
  // click affordance a keyboard-only user gets from a real `<button>`,
  // since this row is a plain `<div>` (see the comment above styles.css's
  // `.con-row-clickable`).
  if(lastConsoleId === 'perimeter'){
    items.forEach(function(item){
      var row = document.createElement('div');
      row.className = 'con-row con-row-clickable';
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.onclick = function(){ openPortModal(item); };
      row.onkeydown = function(e){
        if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); openPortModal(item); }
      };

      var portSpan = document.createElement('span');
      var portK = document.createElement('span');
      portK.className = 'cr-k';
      portK.textContent = (lang === 'ru' ? 'Порт' : 'Port') + ': ';
      portSpan.appendChild(portK);
      var protocolLabel = item.protocol ? String(item.protocol).toUpperCase() : '?';
      portSpan.appendChild(document.createTextNode(String(item.port) + '/' + protocolLabel));
      row.appendChild(portSpan);

      var procSpan = document.createElement('span');
      var procK = document.createElement('span');
      procK.className = 'cr-k';
      procK.textContent = (lang === 'ru' ? 'Процесс' : 'Process') + ': ';
      procSpan.appendChild(procK);
      var procName = item.process_name || (lang === 'ru' ? 'неизвестен' : 'unknown');
      var procLabel = procName + (item.pid != null ? ' (PID ' + item.pid + ')' : '');
      procSpan.appendChild(document.createTextNode(procLabel));
      row.appendChild(procSpan);

      if(item.is_blocked === true){
        var badge = document.createElement('span');
        badge.className = 'port-blocked-badge';
        badge.textContent = lang === 'ru' ? '🔒 Заблокирован' : '🔒 Blocked';
        row.appendChild(badge);
      }

      box.appendChild(row);
    });
    return;
  }
  // A-35: `logs`'s `entries` (real Wazuh FIM findings since A-16, see
  // wazuh.py's `_finding_to_entry` — `timestamp`/`level`/`source`/`file`/
  // `description`) used to fall through to the generic key:value dump
  // below, which printed the raw `level` word and the untouched full file
  // path with no visual severity cue — exactly the "reads as unexplained
  // technical noise" complaint this task fixes. Own branch (like `backup`/
  // `ids` above) instead of extending the generic loop, since a colored
  // level dot and a truncated-with-title path are both per-field
  // treatments the generic loop has no concept of.
  if(lastConsoleId === 'logs'){
    items.forEach(function(item){
      var row = document.createElement('div');
      row.className = 'con-row';

      var levelMeta = describeLogLevel(item.level);
      var lvl = document.createElement('span');
      lvl.className = 'log-lvl log-lvl-' + levelMeta.tone;
      lvl.title = levelMeta[lang];
      var dot = document.createElement('span');
      dot.className = 'log-lvl-dot';
      dot.setAttribute('aria-hidden', 'true');
      var lvlText = document.createElement('span');
      lvlText.textContent = levelMeta[lang];
      lvl.appendChild(dot);
      lvl.appendChild(lvlText);
      row.appendChild(lvl);

      var ts = document.createElement('span');
      ts.className = 'ft';
      ts.textContent = item.timestamp ? formatTimestamp(item.timestamp) : '—';
      row.appendChild(ts);

      if(item.file){
        var fileEl = document.createElement('span');
        fileEl.className = 'log-file';
        fileEl.textContent = truncateFimPath(item.file);
        fileEl.title = item.file; // A-26 pattern: full untruncated value on hover
        row.appendChild(fileEl);
      }

      var desc = document.createElement('span');
      desc.className = 'log-desc';
      desc.textContent = item.description || '';
      row.appendChild(desc);

      box.appendChild(row);
    });
    return;
  }
  // A-34: `network`'s `connections` rows are real (20-30+ on a typical dev
  // machine — see osquery.py's `fetch_network_console_data`) and were
  // falling through to the generic key:value dump below, which is unreadable
  // at that row count. Same architectural move as the `ids` branch above —
  // a dedicated branch ahead of the generic fallback, not an extension of
  // it — rendering the columns the DoD actually asks for: process(+PID),
  // local/remote address:port, a human protocol name, and state.
  //
  // A-39 (11б): two more columns, «Отправлено»/«Получено» — real per-process
  // traffic-byte deltas (`item.bytes_sent`/`item.bytes_received`, see
  // security_console.py._network_payload's own docstring for exactly what
  // they mean and when they are honestly `null`). Shown as a raw byte count
  // via the same `formatValue()` every other raw-byte metric in this file
  // already uses (e.g. backup's `total_size_bytes`, labelled "(байт)" for
  // the same reason) rather than a new KB/MB-formatting helper — `—` for
  // `null` comes for free from `formatValue` itself, no extra branching
  // needed for "first poll, no baseline yet"/"not supported on this OS"/
  // "traffic connector down" — all three collapse to the same honest dash.
  // A-40: two more columns on the same branch — «Страна»/Country (a flag +
  // ISO code, `formatNetworkCountry`, geoip.py's offline resolution) and
  // «Репутация»/Reputation (a red badge on rows CrowdSec's active decisions
  // match, blank otherwise/when not checked — see security_console.py's
  // `_enrich_connections` docstring for the honest 3-state `is_suspicious`
  // this reads). The whole row also gets a soft red tint
  // (`net-row-suspicious`, styles.css) when `is_suspicious === true`, same
  // "className string concat, not classList" style the `backup` branch
  // above already uses for `st-tgl`'s `.on` modifier.
  if(lastConsoleId === 'network'){
    // A-51: real bug found live (2026-08-17) — 9 separate `flex:1 1 110px`
    // columns wrapped onto a second line at typical window widths (their
    // combined min-width exceeded `.con-list-wide`'s own max-width). Local/
    // remote address:port and sent/received bytes are each genuinely ONE
    // idea (an endpoint, a traffic pair) — merged into one column apiece
    // (9 → 7), each rendered as a 2-line `.con-cell-stack` (styles.css) —
    // frees enough width that the remaining columns fit without wrapping,
    // and reads more naturally than 4 separately-labelled columns did.
    var headerRow = document.createElement('div');
    headerRow.className = 'con-row con-row-net';
    headerRow.style.fontWeight = '600';
    headerRow.style.color = 'var(--muted)';
    // Sticky while `.con-list`'s own `overflow-y:auto` scrolls a long
    // connections list — same background/z-index every other floating-
    // over-content element in this file already uses (e.g. `.modal-card`).
    headerRow.style.position = 'sticky';
    headerRow.style.top = '0';
    headerRow.style.background = 'var(--surface)';
    headerRow.style.zIndex = '1';
    // A-39: if the traffic-counters connector itself is not `ok` on this
    // host (see `connectors.os_counters`, same generic per-source status
    // dict `perimeter`/`av` already use — rendered as this console's own
    // error banner just above by the existing generic logic, no new code
    // needed there), the merged bytes column's header explains WHY every
    // row shows a dash instead of leaving that unexplained — same
    // "disabled/empty state always carries a reason" principle (10) as
    // every other honest-placeholder in this panel.
    var trafficStatus = lastConsoleData && lastConsoleData.connectors
      && lastConsoleData.connectors.os_counters && lastConsoleData.connectors.os_counters.status;
    // A-63-7: not_configured gets the full honest explanation (what this
    // is, why it is absent from the Protection stack, why Windows always
    // shows a dash) instead of the generic dead-end "set .env parameters"
    // text — see osCountersHint's own docstring.
    var trafficTip = trafficStatus && trafficStatus !== 'ok'
      ? (trafficStatus === 'not_configured' ? osCountersHint() : translateError('connector_' + trafficStatus))
      : null;
    var headerCols = lang === 'ru'
      ? [
          { flex: '1.5 1 160px', top: 'Процесс' },
          { flex: '1.3 1 150px', top: 'Локальный/Удалённый', sub: 'адрес:порт' },
          { flex: '0.8 1 90px', top: 'Страна' },
          { flex: '0.6 1 66px', top: 'Протокол' },
          { flex: '0.7 1 80px', top: 'Состояние' },
          { flex: '0.8 1 90px', top: 'Отправлено/Получено', sub: 'Кбайт', tip: trafficTip },
          { flex: '1 1 110px', top: 'Репутация' },
        ]
      : [
          { flex: '1.5 1 160px', top: 'Process' },
          { flex: '1.3 1 150px', top: 'Local/Remote', sub: 'address:port' },
          { flex: '0.8 1 90px', top: 'Country' },
          { flex: '0.6 1 66px', top: 'Protocol' },
          { flex: '0.7 1 80px', top: 'State' },
          { flex: '0.8 1 90px', top: 'Sent/Received', sub: 'KB', tip: trafficTip },
          { flex: '1 1 110px', top: 'Reputation' },
        ];
    headerCols.forEach(function(col){
      var cell = document.createElement('span');
      cell.style.flex = col.flex;
      if(col.sub){
        var stack = document.createElement('span');
        stack.className = 'con-cell-stack';
        var top = document.createElement('span');
        top.textContent = col.top;
        stack.appendChild(top);
        var sub = document.createElement('span');
        sub.className = 'con-cell-stack-sub';
        sub.textContent = col.sub;
        stack.appendChild(sub);
        cell.appendChild(stack);
      } else {
        cell.textContent = col.top;
      }
      if(col.tip) cell.title = col.tip;
      headerRow.appendChild(cell);
    });
    box.appendChild(headerRow);

    // A-53: each row is now clickable — opens the connection-detail modal
    // (openConnectionModal, see index.html's #connectionModalOverlay), same
    // `.con-row-clickable` + tabIndex/role/onkeydown keyboard-affordance
    // pattern as `perimeter`'s ports rows above.
    items.forEach(function(item){
      var row = document.createElement('div');
      row.className = 'con-row con-row-net con-row-clickable' + (item.is_suspicious === true ? ' net-row-suspicious' : '');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.onclick = function(){ openConnectionModal(item); };
      row.onkeydown = function(e){
        if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); openConnectionModal(item); }
      };

      var process = document.createElement('span');
      process.className = 'cr-k';
      process.style.flex = '1.5 1 160px';
      var procName = item.process || (lang === 'ru' ? 'неизвестный процесс' : 'unknown process');
      process.textContent = item.pid != null ? procName + ' (' + item.pid + ')' : procName;
      row.appendChild(process);

      // Local/remote merged into one 2-line cell — top = local (this
      // machine's own side, usually the less interesting one), bottom =
      // remote (the other party — where «Страна»/«Репутация» to its right
      // are actually about), same top-to-bottom order the old left-to-right
      // local-then-remote columns already read in.
      var endpoint = document.createElement('span');
      endpoint.style.flex = '1.3 1 150px';
      var endpointStack = document.createElement('span');
      endpointStack.className = 'con-cell-stack';
      var localLine = document.createElement('span');
      localLine.className = 'con-cell-stack-mono';
      localLine.textContent = (lang === 'ru' ? 'Л: ' : 'L: ') + formatNetworkEndpoint(item.local_address, item.local_port);
      endpointStack.appendChild(localLine);
      var remoteLine = document.createElement('span');
      remoteLine.className = 'con-cell-stack-mono';
      remoteLine.textContent = (lang === 'ru' ? 'У: ' : 'R: ') + formatNetworkEndpoint(item.remote_address, item.remote_port);
      endpointStack.appendChild(remoteLine);
      endpoint.appendChild(endpointStack);
      row.appendChild(endpoint);

      var country = document.createElement('span');
      country.style.flex = '0.8 1 90px';
      country.textContent = formatNetworkCountry(item.country);
      row.appendChild(country);

      var protocol = document.createElement('span');
      protocol.style.flex = '0.6 1 66px';
      protocol.textContent = formatNetworkProtocol(item.protocol);
      row.appendChild(protocol);

      var state = document.createElement('span');
      state.style.flex = '0.7 1 80px';
      state.textContent = item.state || '—';
      row.appendChild(state);

      // Sent/received merged into one 2-line cell, converted to KB (was a
      // raw byte count — a typical connection's sent/received is a few
      // KB-MB, not legible as a 6-7 digit byte integer at a glance).
      var bytes = document.createElement('span');
      bytes.style.flex = '0.8 1 90px';
      var bytesStack = document.createElement('span');
      bytesStack.className = 'con-cell-stack';
      var sentLine = document.createElement('span');
      sentLine.className = 'con-cell-stack-mono';
      sentLine.textContent = '↑ ' + formatBytesKb(item.bytes_sent);
      bytesStack.appendChild(sentLine);
      var receivedLine = document.createElement('span');
      receivedLine.className = 'con-cell-stack-mono';
      receivedLine.textContent = '↓ ' + formatBytesKb(item.bytes_received);
      bytesStack.appendChild(receivedLine);
      bytes.appendChild(bytesStack);
      row.appendChild(bytes);

      var reputation = document.createElement('span');
      reputation.style.flex = '1 1 110px';
      if(item.is_suspicious === true){
        reputation.className = 'net-suspicious-badge';
        reputation.textContent = lang === 'ru' ? '⚠ Подозрительный узел' : '⚠ Suspicious host';
        reputation.title = lang === 'ru'
          ? 'Удалённый адрес совпадает с активным решением CrowdSec (бан/каптча).'
          : 'Remote address matches an active CrowdSec decision (ban/captcha).';
      } else {
        reputation.textContent = '—';
      }
      row.appendChild(reputation);

      box.appendChild(row);
    });
    return;
  }
  // Generic fallback for consoles without a dedicated branch above —
  // `perimeter`'s `ports` (A-31), `network`'s `connections` (A-34) and
  // `logs`'s `entries` (A-35) all used to fall through here too ("all
  // empty in Phase 0" — no longer true, see the branches above). This
  // key:value rendering is a reasonable default only for whatever list
  // genuinely has no dedicated branch yet.
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

/* ---------- A-12/A-27/A-28/A-29/A-30: реальные действия консолей
   «Резервные копии», «Вирусная активность», «Периметр», «Обнаружение
   вторжений», «Журналы ОС»/«Сеть» ----------
   A-12 wired `backup` (restic) — the first console with a real tool behind
   its «Управление» buttons. A-27 wires `av` (ClamAV/clamd): quick/full
   scan, reload databases, quarantine list+restore — the backend for
   quick/full scan already existed since A-17, this task just connects it
   (see task report: "самая дешёвая победа"). A-28 wires `perimeter`'s
   rescan. A-29 wires `ids`'s manual ban (unban is per-row, see
   `renderConsole`). A-30 adds `logs`'s on-demand FIM scan (Wazuh) and a
   universal CSV/JSON export shared by `logs`/`network`. Every remaining
   console/button stays a disabled placeholder (A-11 territory) unless a
   later task wires it too. */
var ACTION_HANDLERS = {
  create_snapshot: handleCreateSnapshot,
  restore_system: handleRestoreSystem,
  quick_scan: handleQuickScan,
  full_scan: handleFullScan,
  reload_databases: handleReloadDatabases,
  show_quarantine: handleShowQuarantine,
  // Post-merge user request (2026-08-02)
  custom_scan: handleOpenCustomScanModal,
  update_databases: handleUpdateClamavDatabases,
  rescan_ports: handleRescanPorts,
  crowdsec_ban: handleBanIp,
  // A-30
  trigger_syscheck: handleTriggerSyscheck,
  export_log: handleExportLog,
  // A-36
  firewall_rules: handleFirewallRules,
  block_all_incoming: handleBlockAllIncoming,
  unblock_all_incoming: handleUnblockAllIncoming,
  // A-43
  scenario_thresholds: handleScenarioThresholds,
  // A-45
  scenario_updates_check: handleCheckScenarioUpdates,
};

// A-54: `boxId` defaults to `conActionStatus` (every existing caller keeps
// working unchanged) — `network`'s own export button (moved out of the
// generic «Управление» actions list, see CONSOLE_META.network/renderConsole
// below) passes `conListExportStatus` instead, so its result shows right
// next to the button that triggered it rather than in a section that may
// now be hidden entirely (an empty `actions[]` hides «Управление», see the
// same renderConsole comment).
//
// A-57: `text` may be either a plain string (previous behavior, unchanged)
// or a `{ru, en}` pair. A pair is remembered per box so `applyLang` can
// re-apply it on a language switch without re-running the action (находка
// F3 GUI-прогона 2026-09-19: «Экспортировано записей: 0» осталось
// по-русски на EN-странице). A plain string CLEARS the remembered pair —
// it is already-final text this helper cannot re-translate, so keeping a
// stale pair around would let a later language switch resurrect an old
// message over the newer one.
var conActionStatusLang = {};

// A-63-5 (owner feedback, live 2026-09-21): «нет индикации процесса
// обновления и ничего не понятно» — a busy-state helper for action
// buttons. While a long elevated action runs (freshclam, cscli, netsh…),
// the button shows a distinct pulsating busy label and is disabled
// against double-clicks; the original label comes back when the promise
// settles. Safe to call on a button that has since been re-rendered away
// (the isConnected check makes the late restore a no-op).
function setButtonBusy(btn, busy, busyText){
  if(!btn || !btn.isConnected) return;
  if(busy){
    if(!btn.dataset.busyText) btn.dataset.busyText = btn.textContent;
    btn.textContent = busyText || '…';
    btn.disabled = true;
    btn.classList.add('btn-busy');
  } else {
    btn.classList.remove('btn-busy');
    if(btn.dataset.busyText){
      btn.textContent = btn.dataset.busyText;
      delete btn.dataset.busyText;
    }
    btn.disabled = false;
  }
}

// Wraps a real action handler so the click shows the busy state for as
// long as the handler's promise runs (async handlers return one; a
// synchronous handler restores immediately). Handlers that manage their
// own disabled state keep working — the restore runs after their promise
// settles, so it always wins.
function attachButtonBusyHandler(btn, handler, busyText){
  btn.onclick = function(){
    if(btn.disabled) return;
    setButtonBusy(btn, true, busyText);
    var restore = function(){ setButtonBusy(btn, false); };
    try{
      var outcome = handler(btn);
      if(outcome && typeof outcome.then === 'function'){
        outcome.then(restore, restore);
      } else {
        restore();
      }
    } catch(e){
      restore();
      throw e;
    }
  };
}

function setConActionStatus(text, kind, boxId){
  var box = document.getElementById(boxId || 'conActionStatus');
  if(!box) return;
  if(!text){
    delete conActionStatusLang[box.id];
    box.hidden = true;
    box.textContent = '';
    return;
  }
  var pair = (text && typeof text === 'object') ? text : null;
  if(pair){
    conActionStatusLang[box.id] = { ru: pair.ru, en: pair.en };
  } else {
    delete conActionStatusLang[box.id];
  }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = pair ? (pair[currentLang()] != null ? pair[currentLang()] : (pair.ru || pair.en)) : text;
}

// A-57: re-apply the remembered {ru,en} pairs to every visible action-
// status box after a language switch. Only setConActionStatus writes these
// (a string call clears the pair, a null call deletes it), so what is
// remembered here is always exactly what is on screen.
function reapplyConActionStatusLang(){
  Object.keys(conActionStatusLang).forEach(function(boxId){
    var box = document.getElementById(boxId);
    if(!box || box.hidden) return;
    var pair = conActionStatusLang[boxId];
    var v = pair[currentLang()] != null ? pair[currentLang()] : (pair.ru || pair.en);
    if(v != null) box.textContent = v;
  });
}

// A-57: returns a {ru,en} pair (not pre-translated text) so the action-
// status box re-translates itself on a language switch — see
// setConActionStatus's pair handling. formatValue/formatTimestamp return
// language-neutral digits/dashes for these inputs, so both strings are
// stable regardless of the language active at call time.
function describeBackupJob(job){
  if(job.status === 'success'){
    return {
      ru: 'Готово: ' + formatValue(job.size_bytes) + ' байт, ' + formatTimestamp(job.finished_at),
      en: 'Done: ' + formatValue(job.size_bytes) + ' bytes, ' + formatTimestamp(job.finished_at),
    };
  }
  return {
    ru: 'Операция резервного копирования не удалась.',
    en: 'The backup operation failed.',
  };
}

// A-30: generalized from A-12's console-specific `refreshBackupConsole` —
// same "re-fetch this console's own payload + re-render, without touching
// #conActionStatus" shape, now reusable by any console's action handler
// (backup/logs' own handlers below all call this instead of duplicating
// the fetch+render pair).
async function refreshConsoleData(consoleId){
  if(lastConsoleId !== consoleId) return;
  try{
    var res = await apiFetch(CONSOLE_ROUTES[consoleId]);
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
    await refreshConsoleData('backup');
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
    await refreshConsoleData('backup');
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-30: реальный on-demand FIM-скан (Wazuh) + универсальный
   экспорт списка (logs + network) ----------
   trigger_syscheck — единственная реальная кнопка «Управление» на `logs`
   (см. wazuh.py's WazuhClient.trigger_syscheck — живо проверено против
   реального wazuh-manager:4.14.6, реальный запрос отличается от
   задокументированного Wazuh REST API). export_log — ОДИН обработчик,
   переиспользуемый на ДВУХ консолях (`logs`/`network`, см. CONSOLE_META
   выше) через один и тот же общий серверный эндпоинт
   (server/app/services/security_console_export.py) — не дублирует логику. */

async function handleTriggerSyscheck(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/logs/wazuh/syscheck', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    var lang = currentLang();
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    var affected = body.affected_items || [];
    setConActionStatus(
      affected.length
        ? (lang === 'ru' ? 'Скан запущен для агента: ' + affected.join(', ') : 'Scan restarted for agent: ' + affected.join(', '))
        : (lang === 'ru' ? 'Менеджер не подтвердил ни одного агента.' : 'The manager did not confirm any agent.'),
      affected.length ? 'success' : 'error'
    );
    await refreshConsoleData('logs');
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleExportLog(btn, statusBoxId){
  if(!lastConsoleId || !lastConsoleData) return;
  var meta = CONSOLE_META[lastConsoleId];
  // The exact rows currently rendered in #conList (see renderConsoleList) —
  // exporting anything else (e.g. a fresh re-fetch) would no longer match
  // what the user is looking at on screen, see the server endpoint's own
  // docstring for why that distinction matters.
  var rows = (meta.listKey && lastConsoleData[meta.listKey]) || [];
  if(btn) btn.disabled = true;
  setConActionStatus(null, null, statusBoxId);
  try{
    var res = await apiFetch('/security/consoles/export', {
      method: 'POST',
      body: JSON.stringify({ console_id: lastConsoleId, format: 'csv', rows: rows }),
    });
    if(!res.ok){
      var body = await res.json().catch(function(){ return {}; });
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error', statusBoxId);
      return;
    }
    var blob = await res.blob();
    var disposition = res.headers.get('Content-Disposition') || '';
    var match = /filename="([^"]+)"/.exec(disposition);
    var filename = match ? match[1] : (lastConsoleId + '-export.csv');
    // Bearer-token auth lives in localStorage, not a cookie — a plain
    // `<a href="...">` navigation would never carry it, so the file has to
    // come back through apiFetch() first and get turned into a real
    // browser download via a synthetic, momentary <a download> click.
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    // A-57: {ru,en} pair — the box re-translates itself on a language
    // switch without re-exporting (находка F3, `t10`).
    setConActionStatus(
      {
        ru: 'Экспортировано записей: ' + rows.length,
        en: 'Exported rows: ' + rows.length,
      },
      'success',
      statusBoxId
    );
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error', statusBoxId);
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-27: реальные действия консоли «Вирусная активность» (ClamAV) ----------
   Backend for quick/full scan already existed since A-17
   (services/mcp/security_connectors/clamav.py) — this section is purely
   the frontend wiring, plus the two things that genuinely didn't exist
   yet: a quarantine list+restore view, and "Перечитать базы" (clamd's
   RELOAD). Same `setConActionStatus`/`translateError` plumbing A-12's
   backup handlers above already established, reused as-is. */
var avQuarantineVisible = false;
var lastQuarantineItems = null;
var avFullScanPollTimer = null;
var AV_FULL_SCAN_POLL_MS = 1500;
// A-33: real, persistent scan history (server/app/db/models.py's
// ScanHistory, `GET /security/consoles/av/clamav/scan/history`) — `null`
// until the first fetch completes, distinct from `[]` ("fetched, genuinely
// no scans yet") so renderScanHistoryList never flashes a false-empty
// state before the real data arrives.
var lastScanHistoryItems = null;

function stopAvFullScanPoll(){
  if(avFullScanPollTimer){ clearTimeout(avFullScanPollTimer); avFullScanPollTimer = null; }
}

async function refreshAvConsole(){
  if(lastConsoleId !== 'av') return;
  try{
    var res = await apiFetch(CONSOLE_ROUTES.av);
    if(!res.ok) return;
    lastConsoleData = await res.json();
    renderConsole(); // rebuilds #conActions too — does not touch #conActionStatus
  } catch(e){ /* network hiccup — keep showing the last known console data */ }
}

// A-33: `scan_type` -> a short, readable label for the scan-history list
// below (raw `"quick"`/`"full"`/`"custom"` strings are the wire values,
// never shown to the user as-is — same "translate machine codes client-
// side" principle as ERROR_MESSAGES/translateError).
var SCAN_TYPE_LABELS = {
  quick: { ru: 'Быстрая', en: 'Quick' },
  full: { ru: 'Полная', en: 'Full' },
  custom: { ru: 'Папка', en: 'Folder' },
};

async function fetchAndRenderScanHistory(){
  try{
    var res = await apiFetch('/security/consoles/av/clamav/scan/history');
    if(!res.ok) return false;
    var body = await res.json();
    lastScanHistoryItems = body.items || [];
    if(lastConsoleId === 'av') renderConsole();
    return true;
  } catch(e){ return false; } // network hiccup — keep showing the last known history
}

function renderScanHistoryList(items){
  var box = document.getElementById('avScanHistoryList');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();
  if(!items || items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Сканирований пока не было' : 'No scans yet';
    box.appendChild(empty);
    return;
  }
  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'con-row';

    var type = document.createElement('span');
    type.className = 'cr-k';
    var typeLabel = SCAN_TYPE_LABELS[item.scan_type] || { ru: item.scan_type, en: item.scan_type };
    type.textContent = typeLabel[lang];
    row.appendChild(type);

    if(item.path){
      // A-35-style pattern (long paths truncated visually with a `title`
      // tooltip carrying the full value) reused here rather than
      // reinvented — same reasoning as drawBarChart's canvas.title.
      var path = document.createElement('span');
      path.textContent = item.path;
      path.title = item.path;
      path.style.overflow = 'hidden';
      path.style.textOverflow = 'ellipsis';
      path.style.maxWidth = '260px';
      path.style.whiteSpace = 'nowrap';
      row.appendChild(path);
    }

    var when = document.createElement('span');
    when.style.color = 'var(--muted)';
    when.textContent = formatTimestamp(item.finished_at);
    row.appendChild(when);

    var counts = document.createElement('span');
    counts.style.marginLeft = 'auto';
    counts.textContent = lang === 'ru'
      ? ('проверено: ' + item.scanned_count + ', угроз: ' + item.infected_count)
      : ('scanned: ' + item.scanned_count + ', threats: ' + item.infected_count);
    if(item.infected_count > 0) counts.style.color = 'var(--crit-t)';
    row.appendChild(counts);

    box.appendChild(row);
  });
}

function setCustomScanStatus(text, kind){
  var box = document.getElementById('avCustomScanStatus');
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

async function handleCustomScan(){
  var input = document.getElementById('avCustomScanPath');
  var btn = document.getElementById('avCustomScanBtn');
  if(!input || !btn) return;
  var path = (input.value || '').trim();
  if(!path) return;
  btn.disabled = true;
  setCustomScanStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/clamav/scan/custom', {
      method: 'POST',
      body: JSON.stringify({ path: path }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setCustomScanStatus(translateError(code), 'error');
      return;
    }
    var infected = (body.infected || []).length > 0;
    setCustomScanStatus(describeClamavJob(body), infected ? 'error' : 'success');
    await refreshAvConsole();
    await fetchAndRenderScanHistory();
  } catch(e){
    setCustomScanStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

// Замечание пользователя (2026-08-02): «Проверить папку» переехала из
// инлайн-секции в кнопку «Управления», открывающую эту модалку — тот же
// открыть/закрыть/клик-по-фону паттерн, что и у portModal/
// scenarioThresholdsOverlay (см. app.js's openPortModal/closePortModal).
function handleOpenCustomScanModal(){
  var input = document.getElementById('avCustomScanPath');
  if(input) input.value = '';
  setCustomScanStatus(null);
  document.getElementById('avCustomScanModalOverlay').hidden = false;
}
function closeAvCustomScanModal(){
  var overlay = document.getElementById('avCustomScanModalOverlay');
  if(overlay) overlay.hidden = true;
}
function handleAvCustomScanOverlayClick(e){
  if(e.target && e.target.id === 'avCustomScanModalOverlay') closeAvCustomScanModal();
}

// Замечание пользователя (2026-08-02): «Выбрать папку…» — реальный
// нативный OS-диалог (POST .../pick-folder, см. clamav.py's
// pick_scan_folder), не браузерный file-picker (тот не может отдать JS
// настоящий абсолютный путь). `folder_pick_cancelled` — честный, ожидаемый
// исход (оператор закрыл диалог), не ошибка — тот же нейтральный 'warn'
// стиль, что и `elevation_cancelled` у других elevated-действий этого
// проекта. `unsupported_platform` — честно объясняет, что нативный выбор
// пока только на macOS, текстовое поле остаётся рабочим fallback'ом.
async function handlePickScanFolder(){
  var btn = document.getElementById('avPickFolderBtn');
  var input = document.getElementById('avCustomScanPath');
  if(btn) btn.disabled = true;
  setCustomScanStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/clamav/pick-folder', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      var kind = code === 'folder_pick_cancelled' ? 'warn' : 'error';
      setCustomScanStatus(translateError(code), kind);
      return;
    }
    if(input) input.value = body.path || '';
  } catch(e){
    setCustomScanStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

// Замечание пользователя (2026-08-02): дни недели — 0=Пн...6=Вс, тот же
// порядок, что и бэкенд (Python's datetime.weekday(), см.
// AvSettings.full_scan_days). Короткие подписи под тесную модалку.
var AV_SCHEDULE_DAY_LABELS = [
  { ru: 'Пн', en: 'Mon' }, { ru: 'Вт', en: 'Tue' }, { ru: 'Ср', en: 'Wed' },
  { ru: 'Чт', en: 'Thu' }, { ru: 'Пт', en: 'Fri' }, { ru: 'Сб', en: 'Sat' }, { ru: 'Вс', en: 'Sun' },
];

// Замечание пользователя (2026-08-02): «Расписание полной проверки» —
// теперь настоящая, редактируемая настройка (services/av/), тот же
// открыть/закрыть/сохранить паттерн, что и у scenarioThresholdsOverlay.
function handleOpenAvScheduleModal(){
  var schedule = (lastConsoleData && lastConsoleData.settings && lastConsoleData.settings.full_scan_schedule)
    || { enabled: false, hour: 6, minute: 0, days: [0, 1, 2, 3, 4, 5, 6] };
  var lang = currentLang();
  document.getElementById('avScheduleEnabledInput').checked = !!schedule.enabled;
  document.getElementById('avScheduleHourInput').value = schedule.hour;
  document.getElementById('avScheduleMinuteInput').value = schedule.minute;

  var selectedDays = schedule.days || [];
  var daysBox = document.getElementById('avScheduleDaysBox');
  daysBox.innerHTML = '';
  AV_SCHEDULE_DAY_LABELS.forEach(function(label, dayIndex){
    var wrap = document.createElement('label');
    wrap.className = 'notif-chan-tgl';
    var input = document.createElement('input');
    input.type = 'checkbox';
    input.id = 'avScheduleDay' + dayIndex;
    input.checked = selectedDays.indexOf(dayIndex) !== -1;
    wrap.appendChild(input);
    wrap.appendChild(document.createTextNode(label[lang]));
    daysBox.appendChild(wrap);
  });

  setAvScheduleModalStatus(null);
  document.getElementById('avScheduleModalOverlay').hidden = false;
}
function closeAvScheduleModal(){
  var overlay = document.getElementById('avScheduleModalOverlay');
  if(overlay) overlay.hidden = true;
}
function handleAvScheduleOverlayClick(e){
  if(e.target && e.target.id === 'avScheduleModalOverlay') closeAvScheduleModal();
}
function setAvScheduleModalStatus(text, kind){
  var box = document.getElementById('avScheduleModalStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}
async function handleSaveAvSchedule(){
  var enabled = document.getElementById('avScheduleEnabledInput').checked;
  var hour = parseInt(document.getElementById('avScheduleHourInput').value, 10);
  var minute = parseInt(document.getElementById('avScheduleMinuteInput').value, 10);
  if(isNaN(hour) || hour < 0 || hour > 23 || isNaN(minute) || minute < 0 || minute > 59){
    setAvScheduleModalStatus(
      currentLang() === 'ru' ? 'Время указано некорректно.' : 'Invalid time.', 'error'
    );
    return;
  }
  var days = [];
  AV_SCHEDULE_DAY_LABELS.forEach(function(_label, dayIndex){
    var input = document.getElementById('avScheduleDay' + dayIndex);
    if(input && input.checked) days.push(dayIndex);
  });
  if(enabled && days.length === 0){
    setAvScheduleModalStatus(
      currentLang() === 'ru' ? 'Выберите хотя бы один день недели.' : 'Select at least one day of the week.',
      'error'
    );
    return;
  }
  setAvScheduleModalStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/settings/full-scan-schedule', {
      method: 'POST',
      body: JSON.stringify({ enabled: enabled, hour: hour, minute: minute, days: days }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setAvScheduleModalStatus(translateError(code), 'error');
      return;
    }
    await refreshAvConsole();
    closeAvScheduleModal();
  } catch(e){
    setAvScheduleModalStatus(translateError('network_error'), 'error');
  }
}

// Замечание пользователя (2026-08-02): «Обновить базы» — реальный elevated
// docker exec freshclam (clamav.update_clamav_databases), тот же
// confirm()-перед-elevated-действием паттерн, что и A-36's
// handleBlockAllIncoming/A-45's handleApplyScenarioUpdates.
async function handleUpdateClamavDatabases(btn){
  var lang = currentLang();
  var confirmed = window.confirm(lang === 'ru'
    ? 'Скачать свежие базы сигнатур ClamAV из интернета? Появится системный запрос пароля администратора.'
    : 'Download fresh ClamAV signature databases from the internet? A system administrator-password prompt will appear.');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/clamav/update-databases', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    await refreshAvConsole();
    setConActionStatus(
      lang === 'ru' ? 'Базы сигнатур обновлены.' : 'Signature databases updated.',
      'success'
    );
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function describeClamavJob(job){
  var lang = currentLang();
  var infectedCount = (job.infected || []).length;
  if(job.status === 'completed'){
    if(infectedCount > 0){
      return lang === 'ru'
        ? 'Готово: проверено файлов — ' + job.scanned_count + ', найдено угроз — ' + infectedCount + '.'
        : 'Done: files scanned — ' + job.scanned_count + ', threats found — ' + infectedCount + '.';
    }
    return lang === 'ru'
      ? 'Готово: проверено файлов — ' + job.scanned_count + ', угроз не найдено.'
      : 'Done: files scanned — ' + job.scanned_count + ', no threats found.';
  }
  if(job.status === 'failed'){
    return lang === 'ru'
      ? 'Проверка не удалась: ' + (job.error || '')
      : 'Scan failed: ' + (job.error || '');
  }
  // "running" — shown while a full scan's background job is still in
  // progress (see pollAvFullScan below); scanned_count grows in place as
  // the poll ticks, a real (not simulated) progress indicator.
  return lang === 'ru'
    ? 'Выполняется… проверено файлов пока что: ' + job.scanned_count
    : 'Running… files scanned so far: ' + job.scanned_count;
}

async function handleQuickScan(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/clamav/scan/quick', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    var infected = (body.infected || []).length > 0;
    setConActionStatus(describeClamavJob(body), infected ? 'error' : 'success');
    await refreshAvConsole();
    await fetchAndRenderScanHistory(); // A-33: the just-finished scan now has a real, persisted row
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-29: реальные бан/разбан консоли «Обнаружение вторжений» ----
   Через новый machine-уровня LAPI-логин CrowdSec (см.
   services/mcp/security_connectors/crowdsec.py) — bouncer-ключ, который
   консоль уже использовала для чтения, банить/разбанивать не может. */
async function refreshIdsConsole(){
  if(lastConsoleId !== 'ids') return;
  try{
    var res = await apiFetch(CONSOLE_ROUTES.ids);
    if(!res.ok) return;
    lastConsoleData = await res.json();
    renderConsole(); // rebuilds #conActions/#conList too — does not touch #conActionStatus
  } catch(e){ /* network hiccup — keep showing the last known console data */ }
}

async function handleBanIp(btn){
  var lang = currentLang();
  var ip = window.prompt(lang === 'ru'
    ? 'IP-адрес для бана (например 192.0.2.1):'
    : 'IP address to ban (e.g. 192.0.2.1):', '');
  if(ip == null) return; // cancelled
  ip = ip.trim();
  if(!ip) return;
  var confirmed = window.confirm(lang === 'ru'
    ? 'Забанить IP ' + ip + ' на 4 часа?'
    : 'Ban IP ' + ip + ' for 4 hours?');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/ban', {
      method: 'POST',
      body: JSON.stringify({ ip: ip }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    setConActionStatus(lang === 'ru' ? 'IP ' + ip + ' забанен.' : 'IP ' + ip + ' banned.', 'success');
    await refreshIdsConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-43: модальное окно «Показать/изменить пороги» (CrowdSec) ----------
   «Показать/изменить пороги» на консоли «Обнаружение вторжений» — the
   button click itself IS the one-shot elevated READ (real OS admin prompt,
   same elevated_run() mechanism A-36/A-37 already use) — the modal below
   only ever opens once that read has genuinely succeeded (mirrors
   handleFirewallRules' own "no modal/section shown on cancel/failure, just
   the console-level status box" choice, NOT portModal's "always open
   instantly with already-known data" shape, since there IS no data here
   before this elevated read completes). Each row's own «Сохранить» is then
   its OWN, independent SECOND elevated call (write + restart, server-side)
   — a real OS admin prompt on EVERY save, never batched, never cached,
   exactly the A-37 block/unblock-two-independent-elevated-clicks pattern
   this task's own brief points at. */
var scenarioThresholds = null; // last successfully-read array of {name, type, capacity, leakspeed}

async function handleScenarioThresholds(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/scenario-thresholds');
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    scenarioThresholds = body.scenarios || [];
    renderScenarioThresholdsModal();
    document.getElementById('scenarioThresholdsOverlay').hidden = false;
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function closeScenarioThresholdsModal(){
  var overlay = document.getElementById('scenarioThresholdsOverlay');
  if(overlay) overlay.hidden = true;
}

function handleScenarioThresholdsOverlayClick(e){
  if(e.target && e.target.id === 'scenarioThresholdsOverlay') closeScenarioThresholdsModal();
}

function setScenarioRowStatus(idx, text, kind){
  var box = document.getElementById('scenarioThresholdStatus_' + idx);
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status scenario-threshold-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

function renderScenarioThresholdsModal(){
  var box = document.getElementById('scenarioThresholdsList');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();
  var list = scenarioThresholds || [];

  if(list.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Сценарии не найдены' : 'No scenarios found';
    box.appendChild(empty);
    return;
  }

  list.forEach(function(scenario, idx){
    var row = document.createElement('div');
    row.className = 'con-row scenario-threshold-row';

    var head = document.createElement('div');
    var nameSpan = document.createElement('span');
    nameSpan.className = 'cr-k';
    nameSpan.textContent = scenario.name;
    head.appendChild(nameSpan);
    var typeSpan = document.createElement('span');
    typeSpan.className = 'scenario-threshold-type';
    typeSpan.textContent = scenario.type || '?';
    head.appendChild(typeSpan);
    row.appendChild(head);

    if(scenario.type === 'trigger'){
      // A-43: honest — trigger scenarios have NO capacity/leakspeed
      // concept at all (fire on one matching event), never a fake 0/—
      // editable field (see crowdsec.py's read_scenario_thresholds
      // docstring / this task's own plan document).
      var note = document.createElement('div');
      note.className = 'scenario-threshold-note';
      note.textContent = lang === 'ru'
        ? 'У этого сценария нет понятия порога (срабатывает на одно событие)'
        : 'This scenario has no concept of a threshold (fires on a single matching event)';
      row.appendChild(note);
    } else {
      var form = document.createElement('div');
      form.className = 'scenario-threshold-form';

      var capLabel = document.createElement('label');
      var capLabelText = document.createElement('span');
      capLabelText.textContent = 'capacity:';
      capLabel.appendChild(capLabelText);
      var capInput = document.createElement('input');
      capInput.type = 'number';
      capInput.step = '1';
      capInput.className = 'scenario-cap-input';
      capInput.id = 'scenarioCapInput_' + idx;
      capInput.value = scenario.capacity != null ? scenario.capacity : '';
      capLabel.appendChild(capInput);
      form.appendChild(capLabel);

      var leakLabel = document.createElement('label');
      var leakLabelText = document.createElement('span');
      leakLabelText.textContent = 'leakspeed:';
      leakLabel.appendChild(leakLabelText);
      var leakInput = document.createElement('input');
      leakInput.type = 'text';
      leakInput.placeholder = '10s';
      leakInput.className = 'scenario-leak-input';
      leakInput.id = 'scenarioLeakInput_' + idx;
      leakInput.value = scenario.leakspeed || '';
      leakLabel.appendChild(leakInput);
      form.appendChild(leakLabel);

      var saveBtn = document.createElement('button');
      saveBtn.type = 'button';
      saveBtn.className = 'btn-ghost';
      saveBtn.textContent = lang === 'ru' ? 'Сохранить' : 'Save';
      saveBtn.onclick = (function(rowIdx){ return function(){ handleSaveScenarioThreshold(rowIdx, saveBtn); }; })(idx);
      form.appendChild(saveBtn);

      row.appendChild(form);

      var statusBox = document.createElement('div');
      statusBox.className = 'con-status scenario-threshold-status';
      statusBox.id = 'scenarioThresholdStatus_' + idx;
      statusBox.hidden = true;
      row.appendChild(statusBox);
    }

    box.appendChild(row);
  });
}

async function handleSaveScenarioThreshold(idx, btn){
  var scenario = scenarioThresholds && scenarioThresholds[idx];
  if(!scenario) return;
  var lang = currentLang();
  var capInput = document.getElementById('scenarioCapInput_' + idx);
  var leakInput = document.getElementById('scenarioLeakInput_' + idx);
  var capacityText = capInput ? capInput.value.trim() : '';
  var leakspeed = leakInput ? leakInput.value.trim() : '';
  // Client-side sanity check only — the SAME `\d+[smh]` / int-or--1 rule
  // `crowdsec._validate_capacity`/`_validate_leakspeed` enforce server-side
  // is the actual authority (never trust this check alone, same "client
  // validation is a UX nicety, not the real gate" discipline every other
  // write endpoint in this panel already follows).
  var capacity = parseInt(capacityText, 10);
  if(!capacityText || isNaN(capacity) || String(capacity) !== capacityText){
    setScenarioRowStatus(idx, translateError('invalid_capacity'), 'error');
    return;
  }

  if(btn) btn.disabled = true;
  setScenarioRowStatus(idx, null);
  try{
    var res = await apiFetch(
      '/security/consoles/ids/crowdsec/scenario-thresholds/' + encodeURIComponent(scenario.name),
      { method: 'PUT', body: JSON.stringify({ capacity: capacity, leakspeed: leakspeed }) }
    );
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setScenarioRowStatus(idx, translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    if(body.scenario){
      scenarioThresholds[idx] = body.scenario;
      if(capInput) capInput.value = body.scenario.capacity;
      if(leakInput) leakInput.value = body.scenario.leakspeed;
    }
    setScenarioRowStatus(
      idx,
      lang === 'ru' ? 'Сохранено и применено (readback подтверждён).' : 'Saved and applied (readback confirmed).',
      'success'
    );
  } catch(e){
    setScenarioRowStatus(idx, translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-45: «Проверить обновления»/«Применить обновления» ----------
   Пересматривает решение A-43 не давать «Обновить сценарии» elevated-
   доступ (см. crowdsec.py's «A-45 addendum» докстринг): двухшаговый UX —
   «Проверить обновления» (elevated-клик сам ЕСТЬ разовое чтение, честный
   сырой план `cscli hub upgrade --dry-run` в своей независимой секции, тот
   же принцип «показать реальный вывод инструмента», что уже применён к
   «Правила фаервола» A-36/renderFirewallRulesList) → «Применить
   обновления» (отдельный, ВТОРОЙ elevated-клик, кнопка появляется ТОЛЬКО
   если план показал реальные апгрейды — честная деградация, если
   апгрейдов нет, кнопки нет вообще). */
var idsScenarioUpdatesVisible = false;
var lastScenarioUpdatePlan = null; // {plan, has_upgrades} — последний успешный «Проверить»

function renderScenarioUpdatesPlan(planText){
  var box = document.getElementById('idsScenarioUpdatesList');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();
  // Живая проверка (2026-07-25): macOS-эскалация (`osascript ... do shell
  // script`, elevated.py) возвращает многострочный вывод с разделителем
  // строк `\r`, не `\n` (документированная особенность AppleScript'а) —
  // серверный `crowdsec._parse_scenario_files_output`/os_firewall.py уже
  // разбивают такой вывод через Python's `splitlines()` (сам обрабатывает
  // `\r`/`\r\n`/`\n`), но здесь план — сырая СТРОКА (по спеке задачи, без
  // серверного разбиения на массив) — сплитим по всем трём вариантам,
  // иначе реальный вывод схлопывается в одну строку.
  var lines = (planText || '').split(/\r\n|\r|\n/).filter(function(l){ return l.trim().length > 0; });
  if(lines.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Пустой ответ' : 'Empty response';
    box.appendChild(empty);
    return;
  }
  lines.forEach(function(line){
    var row = document.createElement('div');
    row.className = 'con-row';
    var text = document.createElement('span');
    text.style.fontFamily = 'var(--mono)';
    text.style.fontSize = '11.5px';
    text.style.wordBreak = 'break-all';
    text.textContent = line;
    row.appendChild(text);
    box.appendChild(row);
  });
}

function renderScenarioUpdatesSection(){
  var lang = currentLang();
  renderScenarioUpdatesPlan(lastScenarioUpdatePlan ? lastScenarioUpdatePlan.plan : '');
  var note = document.getElementById('idsScenarioUpdatesNote');
  var applyBtn = document.getElementById('idsScenarioUpdatesApplyBtn');
  var hasUpgrades = !!(lastScenarioUpdatePlan && lastScenarioUpdatePlan.has_upgrades);
  if(note){
    note.hidden = false;
    note.textContent = hasUpgrades
      ? (lang === 'ru'
        ? 'Выше — реальный план CrowdSec (cscli hub upgrade --dry-run): что будет установлено. Ничего ещё не установлено — нажмите «Применить обновления», чтобы установить и перезапустить контейнер.'
        : "Above is CrowdSec's real plan (cscli hub upgrade --dry-run): what would be installed. Nothing has been installed yet — click \"Apply updates\" to install it and restart the container.")
      : (lang === 'ru'
        ? '✅ Все сценарии уже актуальны — устанавливать нечего.'
        : '✅ All scenarios are already up to date — nothing to install.');
  }
  if(applyBtn){
    applyBtn.hidden = !hasUpgrades;
    applyBtn.onclick = function(){ handleApplyScenarioUpdates(applyBtn); };
  }
}

function setScenarioUpdatesApplyStatus(text, kind){
  var box = document.getElementById('idsScenarioUpdatesApplyStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

async function handleCheckScenarioUpdates(btn){
  // Toggle: a second click on an already-open plan closes it — same
  // disclosure pattern handleFirewallRules/handleShowQuarantine already use.
  if(idsScenarioUpdatesVisible){
    idsScenarioUpdatesVisible = false;
    renderConsole();
    return;
  }
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  setScenarioUpdatesApplyStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/scenario-updates/check', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      // `elevation_cancelled` is an honest, expected outcome (the user
      // declined the OS prompt), never conflated with a real failure —
      // shown with the neutral 'warn' status kind, same as A-36/A-43.
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    lastScenarioUpdatePlan = { plan: body.plan || '', has_upgrades: !!body.has_upgrades };
    idsScenarioUpdatesVisible = true;
    renderConsole();
    var lang = currentLang();
    setConActionStatus(
      lastScenarioUpdatePlan.has_upgrades
        ? (lang === 'ru' ? 'Найдены реальные обновления — план показан ниже.' : 'Real updates found — the plan is shown below.')
        : (lang === 'ru' ? 'Все сценарии уже актуальны.' : 'All scenarios are already up to date.'),
      'success'
    );
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleApplyScenarioUpdates(btn){
  var lang = currentLang();
  var confirmed = window.confirm(lang === 'ru'
    ? 'Установить показанные выше обновления сценариев CrowdSec и перезапустить контейнер? Появятся ещё ДВА системных запроса пароля администратора (установка и проверка результата).'
    : 'Install the CrowdSec scenario updates shown above and restart the container? TWO more system administrator-password prompts will appear (install, then verify).');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setScenarioUpdatesApplyStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/scenario-updates/apply', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setScenarioUpdatesApplyStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    lastScenarioUpdatePlan = { plan: body.plan || '', has_upgrades: false };
    renderConsole();
    setScenarioUpdatesApplyStatus(
      lang === 'ru'
        ? (body.applied
          ? 'Обновления установлены, контейнер перезапущен, повторное чтение подтвердило новые версии.'
          : 'Устанавливать было нечего (уже применено ранее) — повторное чтение подтверждает, что всё актуально.')
        : (body.applied
          ? 'Updates installed, the container restarted, and a fresh readback confirmed the new versions.'
          : 'There was nothing left to install (already applied earlier) — a fresh readback confirms everything is current.'),
      'success'
    );
  } catch(e){
    setScenarioUpdatesApplyStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-28: реальное действие консоли «Периметр» ----------
   «Пересканировать порты» — genuinely redundant with the console's own
   auto-refresh (osquery's `listening_ports` query has no cache to
   invalidate, every poll already re-runs it, see osquery.py's own
   docstring), but gives the user a concrete, immediate action to click and
   see confirmed real data, exactly this task's brief. Same
   handler-fetch-refresh shape as `handleCreateSnapshot` above (the only
   other real button in Phase 0 before this task). */
async function refreshPerimeterConsole(){
  if(lastConsoleId !== 'perimeter') return;
  try{
    var res = await apiFetch(CONSOLE_ROUTES.perimeter);
    if(!res.ok) return;
    lastConsoleData = await res.json();
    renderConsole();
  } catch(e){ /* network hiccup — keep showing the last known console data */ }
}

async function handleRescanPorts(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/rescan-ports', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    var connectorStatus = body.connector && body.connector.status;
    if(!res.ok || (connectorStatus && connectorStatus !== 'ok')){
      var code = 'connector_' + (connectorStatus || 'unreachable');
      setConActionStatus(translateError(code), 'error');
      return;
    }
    var lang = currentLang();
    setConActionStatus(
      lang === 'ru'
        ? 'Найдено открытых портов: ' + formatValue(body.open_ports)
        : 'Open ports found: ' + formatValue(body.open_ports),
      'success'
    );
    await refreshPerimeterConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-36: real elevated actions for «Периметр» ----------
   Every one of these three functions makes a request whose SERVER side
   blocks on a real, one-time OS admin-password prompt (osascript/UAC/
   pkexec, see elevated.py) — the click here just waits on a slow fetch;
   there is no way for the browser to show that native dialog itself, only
   to react honestly afterwards to whichever of ok/`elevation_cancelled`/
   `elevation_failed` the server reports back (never showing "cancelled"
   with the same red/alarming styling as a real failure — see the
   `'warn'` status kind used below, and its `.con-status.warn` CSS rule). */
var perimeterRulesVisible = false;
var lastFirewallRules = null;

function renderFirewallRulesList(rules){
  // Замечание пользователя (2026-07-23): раньше писал в #conList (тот же
  // бокс, что и открытые порты) — теперь у правил своя независимая
  // секция (#perimeterFirewallRulesList), список портов больше никогда
  // не подменяется.
  var box = document.getElementById('perimeterFirewallRulesList');
  box.innerHTML = '';
  var lang = currentLang();
  if(!rules || rules.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Правил не найдено' : 'No rules found';
    box.appendChild(empty);
    return;
  }
  rules.forEach(function(line){
    var row = document.createElement('div');
    row.className = 'con-row';
    var text = document.createElement('span');
    text.style.fontFamily = 'var(--mono)';
    text.style.fontSize = '11.5px';
    text.style.wordBreak = 'break-all';
    text.textContent = line;
    row.appendChild(text);
    box.appendChild(row);
  });
}

async function handleFirewallRules(btn){
  // Toggle: a second click on an already-open rule list closes it — same
  // disclosure pattern handleShowQuarantine already uses for `av`'s
  // quarantine list, no extra "hide" button needed.
  if(perimeterRulesVisible){
    perimeterRulesVisible = false;
    renderConsole();
    return;
  }
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/firewall/rules', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      // `elevation_cancelled` is an honest, expected outcome (the user
      // declined the OS prompt), never conflated with a real failure —
      // shown with the neutral 'warn' status kind, not 'error'.
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    lastFirewallRules = body.rules || [];
    perimeterRulesVisible = true;
    // Замечание пользователя (2026-07-23): верхняя плитка «Правил
    // фаервола» всегда показывала «—», даже после успешного считывания
    // здесь — она берётся из lastConsoleData.metrics.firewall_rules,
    // заполняемого ТОЛЬКО пассивным (без запроса прав) GET-опросом при
    // каждом открытии консоли (fetch_firewall_rules, честно
    // permission_denied на macOS без root) — а этот элевейтед-путь
    // (read_firewall_rules) до сих пор обновлял только список ниже, не
    // саму плитку. Раз реальное число уже получено — честно отражаем
    // его и в плитке тоже, а не только в списке.
    if(lastConsoleData && lastConsoleData.metrics){
      lastConsoleData.metrics.firewall_rules = lastFirewallRules.length;
    }
    // Замечание пользователя (2026-07-31): та же причина, что и у плитки
    // выше — верхний баннер «Firewall rules: Недостаточно прав...» тоже
    // читает СВОЙ собственный, отдельный кусок состояния
    // (lastConsoleData.connectors.firewall_rules.status), заполняемый
    // ТОЛЬКО тем же пассивным опросом при открытии консоли, и тоже не
    // обновлялся здесь — поэтому баннер продолжал говорить «недостаточно
    // прав» даже сразу после того, как права только что были успешно
    // получены и список правил уже показан ниже. Раз одноразовое
    // повышение прав только что реально сработало — честно отражаем это
    // и в статусе коннектора, а не только в списке/плитке.
    if(lastConsoleData && lastConsoleData.connectors && lastConsoleData.connectors.firewall_rules){
      lastConsoleData.connectors.firewall_rules = { status: 'ok' };
    }
    renderConsole();
    var lang = currentLang();
    setConActionStatus(
      lang === 'ru' ? ('Правил получено: ' + lastFirewallRules.length) : ('Rules retrieved: ' + lastFirewallRules.length),
      'success'
    );
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleBlockAllIncoming(btn){
  var lang = currentLang();
  // A-29 pattern: an explicit window.confirm() before any wide-blast-
  // radius action, same as CrowdSec's manual ban — this one is worded to
  // spell out the actual risk (may cut off legitimate local services) and
  // to set the expectation that a real system password prompt follows.
  var confirmed = window.confirm(lang === 'ru'
    ? 'Заблокировать ВЕСЬ входящий трафик? Это может отрезать легитимные локальные сервисы на этой машине (например, общий доступ к файлам, удалённые подключения). Сейчас появится системный запрос пароля администратора.'
    : 'Block ALL incoming traffic? This may cut off legitimate local services on this machine (e.g. file sharing, remote connections). A system administrator password prompt will appear next.');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/firewall/block-all', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    setConActionStatus(
      lang === 'ru' ? '🔒 Весь входящий трафик заблокирован.' : '🔒 All incoming traffic is now blocked.',
      'success'
    );
    await refreshPerimeterConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleUnblockAllIncoming(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/firewall/unblock-all', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    var lang = currentLang();
    setConActionStatus(
      lang === 'ru'
        ? 'Блокировка снята — восстановлены исходные правила фаервола.'
        : 'Block removed — the original firewall rules are restored.',
      'success'
    );
    await refreshPerimeterConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

/* ---------- A-37: модальное окно деталей порта ---------- */
/* Opened by a click/Enter on a `perimeter` ports row (renderConsoleList's
   `perimeter` branch above) — `portModalItem` is a snapshot of that ROW's
   own data (`{port, protocol, pid, process_name, is_blocked}`, exactly
   security_console.py._perimeter_payload's `ports[]` shape), not re-fetched
   from the server on open: the operator just saw this exact row in the
   table, a live consistency check on every single click would be
   pointless extra latency for data that is, at worst, a few seconds stale
   (see A-39's own `network` auto-refresh — `perimeter` does not poll that
   aggressively, so "stale" here realistically means "since the console was
   last opened/refreshed", the same staleness every other console-level
   value already carries). `handleBlockPort`/`handleUnblockPort` update
   `is_blocked` on this SAME object in place once the server confirms the
   action, so the modal reflects the real new state without needing a
   fresh fetch either. */
var portModalItem = null;

function openPortModal(item){
  portModalItem = item;
  setPortModalStatus(null);
  renderPortModal();
  document.getElementById('portModalOverlay').hidden = false;
}

function closePortModal(){
  var overlay = document.getElementById('portModalOverlay');
  if(overlay) overlay.hidden = true;
  portModalItem = null;
}

// Closes on a click on the dimmed backdrop itself, NOT on a click anywhere
// inside `.modal-card` (event target check, same "only the actual overlay
// element, not a bubbled child click" pattern a plain window.confirm()
// never needed but a real custom overlay does).
function handlePortModalOverlayClick(e){
  if(e.target && e.target.id === 'portModalOverlay') closePortModal();
}

function setPortModalStatus(text, kind){
  var box = document.getElementById('portModalStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

function renderPortModal(){
  if(!portModalItem) return;
  var lang = currentLang();
  var box = document.getElementById('portModalDetails');
  box.innerHTML = '';

  var protocolLabel = portModalItem.protocol ? String(portModalItem.protocol).toUpperCase() : '?';
  var procName = portModalItem.process_name || (lang === 'ru' ? 'неизвестен' : 'unknown');
  var rows = [
    [lang === 'ru' ? 'Порт' : 'Port', String(portModalItem.port) + '/' + protocolLabel],
    [lang === 'ru' ? 'Процесс' : 'Process', procName],
    [lang === 'ru' ? 'PID' : 'PID', portModalItem.pid != null ? String(portModalItem.pid) : '—'],
    [lang === 'ru' ? 'Состояние' : 'Status', portModalItem.is_blocked
      ? (lang === 'ru' ? '🔒 Заблокирован' : '🔒 Blocked')
      : (lang === 'ru' ? 'Открыт' : 'Open')],
  ];
  rows.forEach(function(pair){
    var row = document.createElement('div');
    row.className = 'con-row';
    var k = document.createElement('span');
    k.className = 'cr-k';
    k.textContent = pair[0] + ': ';
    row.appendChild(k);
    row.appendChild(document.createTextNode(pair[1]));
    box.appendChild(row);
  });

  // The button matching the CURRENT state is disabled — mirrors
  // `.btn-accent:disabled`/`.btn-danger:disabled`'s existing "nothing to
  // do" convention every other action button in this panel already uses,
  // rather than letting a click fire a request the server would just
  // treat as a harmless no-op anyway.
  document.getElementById('portModalBlockBtn').disabled = portModalItem.is_blocked === true;
  document.getElementById('portModalUnblockBtn').disabled = portModalItem.is_blocked !== true;
}

async function handleBlockPort(){
  if(!portModalItem) return;
  var port = portModalItem.port;
  var lang = currentLang();
  document.getElementById('portModalBlockBtn').disabled = true;
  document.getElementById('portModalUnblockBtn').disabled = true;
  setPortModalStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/ports/' + encodeURIComponent(port) + '/block', {
      method: 'POST',
      body: JSON.stringify({
        protocol: portModalItem.protocol || null,
        process_name: portModalItem.process_name || null,
      }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setPortModalStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    portModalItem.is_blocked = true;
    setPortModalStatus(lang === 'ru' ? ('🔒 Порт ' + port + ' заблокирован.') : ('🔒 Port ' + port + ' blocked.'), 'success');
    await refreshPerimeterConsole();
  } catch(e){
    setPortModalStatus(translateError('network_error'), 'error');
  } finally {
    renderPortModal(); // re-syncs both buttons' disabled state either way
  }
}

async function handleUnblockPort(){
  if(!portModalItem) return;
  var port = portModalItem.port;
  var lang = currentLang();
  document.getElementById('portModalBlockBtn').disabled = true;
  document.getElementById('portModalUnblockBtn').disabled = true;
  setPortModalStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/ports/' + encodeURIComponent(port) + '/block', {
      method: 'DELETE',
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setPortModalStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    portModalItem.is_blocked = false;
    setPortModalStatus(
      lang === 'ru' ? ('Блокировка порта ' + port + ' снята.') : ('Port ' + port + ' unblocked.'), 'success'
    );
    await refreshPerimeterConsole();
  } catch(e){
    setPortModalStatus(translateError('network_error'), 'error');
  } finally {
    renderPortModal();
  }
}

/* ---------- A-53: модальное окно деталей активного соединения ---------- */
/* Opened by a click/Enter on a `network` connections row (renderConsoleList's
   `network` branch above) — `connectionModalItem` is a snapshot of that
   ROW's own data (the exact `_enrich_connections()` shape, see
   security_console.py), same "no re-fetch on open, the operator just saw
   this exact row" reasoning as `portModalItem` above. `handleBlockConnectionIp`
   updates `is_blocked` on this SAME object in place once the server
   confirms the block, mirroring `handleBlockPort`. Terminating a process has
   no equivalent in-place field to update (see os_processes.py's own
   docstring: no persisted "currently applied" state for a one-off SIGTERM) —
   success just reports the outcome and refreshes the underlying table. */
var connectionModalItem = null;

function openConnectionModal(item){
  connectionModalItem = item;
  setConnectionModalStatus(null);
  renderConnectionModal();
  document.getElementById('connectionModalOverlay').hidden = false;
}

function closeConnectionModal(){
  var overlay = document.getElementById('connectionModalOverlay');
  if(overlay) overlay.hidden = true;
  connectionModalItem = null;
}

function handleConnectionModalOverlayClick(e){
  if(e.target && e.target.id === 'connectionModalOverlay') closeConnectionModal();
}

function setConnectionModalStatus(text, kind){
  var box = document.getElementById('connectionModalStatus');
  if(!box) return;
  if(!text){ box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

function renderConnectionModal(){
  if(!connectionModalItem) return;
  var lang = currentLang();
  var item = connectionModalItem;
  var box = document.getElementById('connectionModalDetails');
  box.innerHTML = '';

  var procName = item.process || (lang === 'ru' ? 'неизвестный процесс' : 'unknown process');
  var procLabel = item.pid != null ? procName + ' (PID ' + item.pid + ')' : procName;
  var rows = [
    [lang === 'ru' ? 'Процесс' : 'Process', procLabel],
    [lang === 'ru' ? 'Локальный адрес' : 'Local address', formatNetworkEndpoint(item.local_address, item.local_port)],
    [lang === 'ru' ? 'Удалённый адрес' : 'Remote address', formatNetworkEndpoint(item.remote_address, item.remote_port)],
    [lang === 'ru' ? 'Страна' : 'Country', formatNetworkCountry(item.country)],
    [lang === 'ru' ? 'Протокол' : 'Protocol', formatNetworkProtocol(item.protocol)],
    [lang === 'ru' ? 'Состояние' : 'State', item.state || '—'],
    [lang === 'ru' ? 'Отправлено/Получено' : 'Sent/Received',
      '↑ ' + formatBytesKb(item.bytes_sent) + ' / ↓ ' + formatBytesKb(item.bytes_received) + ' ' + (lang === 'ru' ? 'КБ' : 'KB')],
    [lang === 'ru' ? 'Репутация' : 'Reputation', item.is_suspicious === true
      ? (lang === 'ru' ? '⚠ Подозрительный узел' : '⚠ Suspicious host')
      : '—'],
    [lang === 'ru' ? 'IP-адрес' : 'IP address', item.is_blocked === true
      ? (lang === 'ru' ? '🔒 Заблокирован' : '🔒 Blocked')
      : (lang === 'ru' ? 'Не заблокирован' : 'Not blocked')],
  ];
  rows.forEach(function(pair){
    var row = document.createElement('div');
    row.className = 'con-row';
    var k = document.createElement('span');
    k.className = 'cr-k';
    k.textContent = pair[0] + ': ';
    row.appendChild(k);
    row.appendChild(document.createTextNode(pair[1]));
    box.appendChild(row);
  });

  // «Заблокировать IP» needs an actual remote address to block, and is
  // pointless (disabled) once already blocked — same "nothing to do"
  // disabled convention `portModalBlockBtn`/`portModalUnblockBtn` above
  // already use. «Завершить процесс» needs a real PID — some rows
  // genuinely have none (see security_console.py's own honest-null
  // reasoning for `pid`).
  document.getElementById('connectionModalBlockIpBtn').disabled =
    !item.remote_address || item.is_blocked === true;
  document.getElementById('connectionModalTerminateBtn').disabled = item.pid == null;
}

async function handleBlockConnectionIp(){
  if(!connectionModalItem) return;
  var ip = connectionModalItem.remote_address;
  if(!ip) return;
  var lang = currentLang();
  document.getElementById('connectionModalBlockIpBtn').disabled = true;
  document.getElementById('connectionModalTerminateBtn').disabled = true;
  setConnectionModalStatus(null);
  try{
    var res = await apiFetch('/security/consoles/network/ips/' + encodeURIComponent(ip) + '/block', {
      method: 'POST',
      body: JSON.stringify({
        country: connectionModalItem.country || null,
        process_name: connectionModalItem.process || null,
        reason: lang === 'ru'
          ? 'Заблокировано вручную из карточки соединения на панели.'
          : 'Manually blocked from the connection card in the panel.',
      }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConnectionModalStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    connectionModalItem.is_blocked = true;
    setConnectionModalStatus(lang === 'ru' ? ('🔒 IP ' + ip + ' заблокирован.') : ('🔒 IP ' + ip + ' blocked.'), 'success');
    await refreshNetworkConsole();
  } catch(e){
    setConnectionModalStatus(translateError('network_error'), 'error');
  } finally {
    renderConnectionModal(); // re-syncs both buttons' disabled state either way
  }
}

// Two SEPARATE window.confirm() dialogs, deliberately not one — the user's
// own explicit request for this action was "максимально мягко и защищённо
// с предупреждениями несколько раз" (as soft/protected as possible, with
// several warnings). Each confirm is worded differently (what will happen,
// then a final "are you sure" naming the exact process/PID) rather than
// showing the same text twice, so a reflexive double-click-through does not
// defeat the point of asking twice. This is layer (2) of the four-layer
// defense described in index.html's own A-53 comment above
// #connectionModalOverlay; layers (3)/(4) — the real OS password prompt and
// the in-script PID/name re-check — live server-side in os_processes.py.
async function handleTerminateConnectionProcess(){
  if(!connectionModalItem) return;
  var item = connectionModalItem;
  if(item.pid == null) return;
  var lang = currentLang();
  var procName = item.process || (lang === 'ru' ? 'неизвестный процесс' : 'unknown process');

  var firstConfirmText = lang === 'ru'
    ? ('Процесс «' + procName + '» (PID ' + item.pid + ') будет завершён (SIGTERM). Это может привести к потере несохранённых данных в этом процессе. Продолжить?')
    : ('The process "' + procName + '" (PID ' + item.pid + ') will be terminated (SIGTERM). This may lose unsaved data in that process. Continue?');
  if(!window.confirm(firstConfirmText)) return;

  var secondConfirmText = lang === 'ru'
    ? ('Подтвердите ещё раз: действительно завершить PID ' + item.pid + ' («' + procName + '»)? Действие потребует пароль администратора и необратимо.')
    : ('Confirm once more: really terminate PID ' + item.pid + ' ("' + procName + '")? This requires an administrator password and cannot be undone.');
  if(!window.confirm(secondConfirmText)) return;

  document.getElementById('connectionModalBlockIpBtn').disabled = true;
  document.getElementById('connectionModalTerminateBtn').disabled = true;
  setConnectionModalStatus(null);
  try{
    var res = await apiFetch('/security/consoles/network/processes/' + encodeURIComponent(item.pid) + '/terminate', {
      method: 'POST',
      body: JSON.stringify({ process_name: procName }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConnectionModalStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    setConnectionModalStatus(
      lang === 'ru' ? ('Процесс ' + procName + ' (PID ' + item.pid + ') завершён.') : ('Process ' + procName + ' (PID ' + item.pid + ') terminated.'),
      'success'
    );
    await refreshNetworkConsole();
  } catch(e){
    setConnectionModalStatus(translateError('network_error'), 'error');
  } finally {
    renderConnectionModal();
  }
}


// ---------------------------------------------------------------------------
// A-38: «Текущая сеть» — display + manual category toggle, and the
// persistent «Известные сети» list. Deliberately NOT elevated (unlike the
// A-36 firewall actions above): writing to this app's own DB needs no OS
// admin prompt, only reading pf/firewall state does.
// ---------------------------------------------------------------------------

var ID_KIND_LABELS = {
  ssid: { ru: 'имя сети (SSID)', en: 'network name (SSID)' },
  gateway_ip: { ru: 'по IP шлюза — точное имя недоступно на этой машине', en: 'by gateway IP — exact name unavailable on this machine' },
  connection_uuid: { ru: 'по идентификатору подключения (NetworkManager)', en: 'by connection identifier (NetworkManager)' },
  os_profile: { ru: 'профиль ОС (Windows)', en: 'OS profile (Windows)' },
};

function setNetworkProfileStatus(text, kind){
  var box = document.getElementById('perimeterNetworkStatus');
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

function renderPerimeterNetworkProfile(networkProfile){
  var lang = currentLang();
  var nameEl = document.getElementById('perimeterNetworkName');
  var badgeEl = document.getElementById('perimeterNetworkCategoryBadge');
  var hintEl = document.getElementById('perimeterNetworkHint');
  var toggleBtn = document.getElementById('perimeterNetworkToggleBtn');
  if(!nameEl || !badgeEl || !toggleBtn) return;

  var current = networkProfile.current || {};
  if(!current.network_key){
    // Honest "no current network" state (A-38 DoD) — same disabled-
    // placeholder-with-explanation convention (principle 10) as every
    // other honestly-unavailable control in this panel, never a blank
    // silence.
    nameEl.textContent = lang === 'ru' ? 'Сеть не определена' : 'No network detected';
    badgeEl.textContent = '';
    badgeEl.className = 'st-tgl';
    hintEl.hidden = true;
    toggleBtn.disabled = true;
    toggleBtn.textContent = lang === 'ru' ? 'Назначить категорию' : 'Assign category';
    toggleBtn.title = translateError('connector_' + ((networkProfile.connector && networkProfile.connector.status) || 'not_connected'));
    return;
  }

  nameEl.textContent = current.display_name || current.network_key;
  var isTrusted = current.category === 'trusted';
  badgeEl.className = 'st-tgl' + (isTrusted ? ' on' : ' warn');
  badgeEl.textContent = isTrusted
    ? (lang === 'ru' ? 'доверенная' : 'trusted')
    : (lang === 'ru' ? 'публичная' : 'public');

  // A-38: an honest note whenever the network's identity is NOT a real
  // human-readable name (see network_profile.py's own docstring for the
  // live-confirmed macOS SSID-read limitation this covers) — never
  // presents a gateway-IP-based fallback key as if it were a real SSID.
  if(current.id_kind && current.id_kind !== 'ssid'){
    var idLabel = ID_KIND_LABELS[current.id_kind];
    hintEl.hidden = false;
    hintEl.textContent = (lang === 'ru' ? 'Определено ' : 'Identified ')
      + (idLabel ? idLabel[lang] : current.id_kind);
  } else {
    hintEl.hidden = true;
  }

  toggleBtn.disabled = false;
  toggleBtn.textContent = isTrusted
    ? (lang === 'ru' ? 'Сделать публичной' : 'Mark as public')
    : (lang === 'ru' ? 'Сделать доверенной' : 'Mark as trusted');
  toggleBtn.title = '';
}

function renderKnownNetworksList(items){
  var box = document.getElementById('perimeterKnownNetworksList');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();
  if(!items || items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Известных сетей пока нет' : 'No known networks yet';
    box.appendChild(empty);
    return;
  }
  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'con-row';

    var name = document.createElement('span');
    name.className = 'cr-k';
    name.textContent = item.display_name || item.network_key;
    row.appendChild(name);

    var badge = document.createElement('span');
    var isTrusted = item.category === 'trusted';
    badge.className = 'st-tgl' + (isTrusted ? ' on' : ' warn');
    badge.textContent = isTrusted
      ? (lang === 'ru' ? 'доверенная' : 'trusted')
      : (lang === 'ru' ? 'публичная' : 'public');
    row.appendChild(badge);

    var seen = document.createElement('span');
    seen.style.marginLeft = 'auto';
    seen.style.color = 'var(--muted)';
    seen.textContent = formatTimestamp(item.last_seen_at);
    row.appendChild(seen);

    box.appendChild(row);
  });
}

async function handleToggleNetworkCategory(){
  var btn = document.getElementById('perimeterNetworkToggleBtn');
  var current = (lastConsoleData && lastConsoleData.network_profile && lastConsoleData.network_profile.current) || {};
  if(!current.network_key) return;
  var nextCategory = current.category === 'trusted' ? 'public' : 'trusted';
  if(btn) btn.disabled = true;
  setNetworkProfileStatus(null);
  try{
    var res = await apiFetch('/security/consoles/perimeter/network-profile/category', {
      method: 'POST',
      body: JSON.stringify({ category: nextCategory }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setNetworkProfileStatus(translateError(code), 'error');
      return;
    }
    lastConsoleData.network_profile = body;
    var lang = currentLang();
    setNetworkProfileStatus(
      nextCategory === 'trusted'
        ? (lang === 'ru' ? 'Сеть отмечена как доверенная.' : 'Network marked as trusted.')
        : (lang === 'ru' ? 'Сеть отмечена как публичная.' : 'Network marked as public.'),
      'success'
    );
    renderConsole();
  } catch(e){
    setNetworkProfileStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// A-42/A-44: «Белый список» — real CrowdSec allowlist entries, now
// readable AND writable. Read shape unchanged from A-42 (same "list +
// honest empty + honest not-checked" pattern as A-38's
// renderKnownNetworksList/renderPerimeterNetworkProfile above, just on the
// `ids` console instead of `perimeter`) — A-44 adds the inline add-form
// (handleAddToAllowlist, own idsAllowlistSection markup in index.html,
// same pattern as A-33's «Проверить папку»/handleCustomScan) and a
// per-row «Удалить» button (handleRemoveFromAllowlist, same pattern as
// A-43's «Сохранить» on each scenario-threshold row/A-29's «Разбанить» on
// each recent_attempts row) — both real, one-shot elevated docker-exec
// writes (crowdsec.py's add_to_allowlist/remove_from_allowlist).
// ---------------------------------------------------------------------------

function renderIdsAllowlist(allowlist){
  var box = document.getElementById('idsAllowlistList');
  if(!box) return;
  box.innerHTML = '';
  var lang = currentLang();

  var status = (allowlist.connector && allowlist.connector.status) || 'not_configured';
  if(status !== 'ok'){
    // A-42 DoD (honest degradation): CrowdSec's allowlist endpoint not
    // configured/unreachable/unauthorized must read as "not checked", NEVER
    // as "Белый список пуст" (which would claim a real check found
    // nothing) — same distinction A-32's ids status banner and A-38's "no
    // current network" state already make elsewhere in this file.
    var reasonKey = status === 'not_configured' ? 'crowdsec_write_not_configured' : 'crowdsec_' + status;
    var notChecked = document.createElement('div');
    notChecked.className = 'con-empty';
    notChecked.textContent = translateError(reasonKey);
    box.appendChild(notChecked);
    return;
  }

  var items = allowlist.items || [];
  if(items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'Белый список пуст' : 'Allowlist is empty';
    box.appendChild(empty);
    return;
  }

  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'con-row';

    var value = document.createElement('span');
    value.className = 'cr-k';
    value.textContent = item.value || '—';
    row.appendChild(value);

    if(item.comment){
      var comment = document.createElement('span');
      comment.textContent = item.comment;
      row.appendChild(comment);
    }

    var expiration = document.createElement('span');
    expiration.style.marginLeft = 'auto';
    expiration.style.color = 'var(--muted)';
    expiration.textContent = item.expiration
      ? formatTimestamp(item.expiration)
      : (lang === 'ru' ? 'бессрочно' : 'no expiry');
    row.appendChild(expiration);

    // A-44: real per-row delete — its own independent elevated call (same
    // "no batching, no caching" discipline as A-43's per-scenario
    // «Сохранить»/A-29's per-decision «Разбанить»), never blocked on
    // `item.value` being falsy since every real allowlist entry always has
    // one (see crowdsec.py's `_flatten_allowlist_items`).
    var removeBtn = document.createElement('button');
    removeBtn.className = 'btn-ghost';
    removeBtn.type = 'button';
    removeBtn.textContent = lang === 'ru' ? 'Удалить' : 'Remove';
    removeBtn.disabled = !item.value;
    removeBtn.onclick = (function(value){ return function(){ handleRemoveFromAllowlist(value, removeBtn); }; })(item.value);
    row.appendChild(removeBtn);

    box.appendChild(row);
  });
}

function setAllowlistAddStatus(text, kind){
  var box = document.getElementById('idsAllowlistAddStatus');
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

async function handleAddToAllowlist(){
  var valueInput = document.getElementById('idsAllowlistValueInput');
  var commentInput = document.getElementById('idsAllowlistCommentInput');
  var btn = document.getElementById('idsAllowlistAddBtn');
  if(!valueInput || !btn) return;
  var value = (valueInput.value || '').trim();
  var comment = commentInput ? (commentInput.value || '').trim() : '';
  if(!value) return;

  btn.disabled = true;
  setAllowlistAddStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/allowlist', {
      method: 'POST',
      body: JSON.stringify({ value: value, comment: comment || null }),
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setAllowlistAddStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    var lang = currentLang();
    setAllowlistAddStatus(
      lang === 'ru' ? value + ' добавлен в белый список.' : value + ' added to the allowlist.',
      'success'
    );
    valueInput.value = '';
    if(commentInput) commentInput.value = '';
    await refreshIdsConsole();
  } catch(e){
    setAllowlistAddStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

async function handleRemoveFromAllowlist(value, btn){
  var lang = currentLang();
  var confirmed = window.confirm(
    lang === 'ru' ? 'Удалить ' + value + ' из белого списка?' : 'Remove ' + value + ' from the allowlist?'
  );
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/allowlist/' + encodeURIComponent(value), {
      method: 'DELETE',
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), code === 'elevation_cancelled' ? 'warn' : 'error');
      return;
    }
    setConActionStatus(
      lang === 'ru' ? value + ' удалён из белого списка.' : value + ' removed from the allowlist.',
      'success'
    );
    await refreshIdsConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function pollAvFullScan(jobId, btn){
  stopAvFullScanPoll();
  avFullScanPollTimer = setTimeout(async function(){
    try{
      var res = await apiFetch('/security/consoles/av/clamav/scan/full/' + encodeURIComponent(jobId));
      if(!res.ok){
        // Job vanished/console-level auth issue mid-poll — stop rather
        // than loop forever against an endpoint that will keep failing.
        stopAvFullScanPoll();
        if(btn) btn.disabled = false;
        return;
      }
      var body = await res.json();
      if(body.status === 'running'){
        setConActionStatus(describeClamavJob(body));
        pollAvFullScan(jobId, btn);
        return;
      }
      var infected = (body.infected || []).length > 0;
      setConActionStatus(describeClamavJob(body), body.status === 'failed' || infected ? 'error' : 'success');
      stopAvFullScanPoll();
      if(btn) btn.disabled = false;
      await refreshAvConsole();
      await fetchAndRenderScanHistory(); // A-33: pick up the full scan's own persisted row
    } catch(e){
      // Network hiccup mid-poll — the background job itself is unaffected
      // server-side, so keep trying rather than abandoning the operator
      // with a stuck "running" status.
      pollAvFullScan(jobId, btn);
    }
  }, AV_FULL_SCAN_POLL_MS);
}

async function handleFullScan(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  stopAvFullScanPoll();
  try{
    var res = await apiFetch('/security/consoles/av/clamav/scan/full', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      if(btn) btn.disabled = false;
      return;
    }
    // A full scan can genuinely take minutes (see start_full_scan's own
    // docstring) — the button stays disabled and the status line shows
    // real, polled progress until the job actually finishes, rather than
    // "sent and forgotten" (this task's own DoD requirement).
    setConActionStatus(describeClamavJob(body));
    pollAvFullScan(body.id, btn);
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
    if(btn) btn.disabled = false;
  }
}

async function handleReloadDatabases(btn){
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/av/clamav/reload', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    setConActionStatus(
      currentLang() === 'ru' ? 'Базы сигнатур перечитаны с диска.' : 'Signature databases reread from disk.',
      'success'
    );
    await refreshAvConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
  } finally {
    if(btn) btn.disabled = false;
  }
}

function renderQuarantineList(items){
  var box = document.getElementById('conList');
  box.innerHTML = '';
  // A-40: defensive reset — see renderConsoleList's identical comment.
  // Only reachable from the `av` console's own "Карантин" action, which
  // already reset this to plain 'con-list' on its way here, but resetting
  // explicitly costs nothing and never depends on that call order holding.
  box.className = 'con-list';
  var lang = currentLang();
  if(!items || items.length === 0){
    var empty = document.createElement('div');
    empty.className = 'con-empty';
    empty.textContent = lang === 'ru' ? 'В карантине пусто' : 'Quarantine is empty';
    box.appendChild(empty);
    return;
  }
  items.forEach(function(item){
    var row = document.createElement('div');
    row.className = 'con-row';

    var path = document.createElement('span');
    path.className = 'cr-k';
    path.textContent = item.original_path;
    row.appendChild(path);

    var when = document.createElement('span');
    when.style.color = 'var(--muted)';
    when.textContent = formatTimestamp(item.quarantined_at);
    row.appendChild(when);

    var reason = document.createElement('span');
    reason.textContent = item.reason || (lang === 'ru' ? 'причина неизвестна' : 'reason unknown');
    row.appendChild(reason);

    var restoreBtn = document.createElement('button');
    restoreBtn.className = 'btn-ghost';
    restoreBtn.type = 'button';
    restoreBtn.style.marginLeft = 'auto';
    restoreBtn.textContent = lang === 'ru' ? 'Восстановить' : 'Restore';
    restoreBtn.onclick = function(){ handleRestoreQuarantineFile(item.id, restoreBtn); };
    row.appendChild(restoreBtn);

    box.appendChild(row);
  });
}

async function fetchAndRenderQuarantineList(){
  try{
    var res = await apiFetch('/security/consoles/av/clamav/quarantine');
    if(!res.ok) return false;
    var body = await res.json();
    lastQuarantineItems = body.items || [];
    avQuarantineVisible = true;
    renderConsole();
    return true;
  } catch(e){ return false; }
}

async function handleShowQuarantine(btn){
  // Toggle: a second click on an already-open quarantine list closes it —
  // same disclosure pattern as re-clicking to dismiss, no extra button
  // needed for "hide".
  if(avQuarantineVisible){
    avQuarantineVisible = false;
    renderConsole();
    return;
  }
  if(btn) btn.disabled = true;
  setConActionStatus(null);
  var ok = await fetchAndRenderQuarantineList();
  if(!ok) setConActionStatus(translateError('network_error'), 'error');
  if(btn) btn.disabled = false;
}

async function handleRestoreQuarantineFile(itemId, btn){
  if(btn) btn.disabled = true;
  try{
    var res = await apiFetch(
      '/security/consoles/av/clamav/quarantine/' + encodeURIComponent(itemId) + '/restore',
      { method: 'POST' }
    );
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      if(btn) btn.disabled = false;
      return;
    }
    setConActionStatus(
      currentLang() === 'ru' ? ('Восстановлено: ' + body.restored_path) : ('Restored: ' + body.restored_path),
      'success'
    );
    // Refreshes the quarantine list (the restored item disappears) AND the
    // console's own metrics (quarantine_count drops by one) — two
    // different real states, both worth reflecting immediately.
    await fetchAndRenderQuarantineList();
    await refreshAvConsole();
  } catch(e){
    setConActionStatus(translateError('network_error'), 'error');
    if(btn) btn.disabled = false;
  }
}

async function handleUnbanIp(decisionId, ip, btn){
  var lang = currentLang();
  var confirmed = window.confirm(lang === 'ru' ? 'Разбанить IP ' + ip + '?' : 'Unban IP ' + ip + '?');
  if(!confirmed) return;

  if(btn) btn.disabled = true;
  setConActionStatus(null);
  try{
    var res = await apiFetch('/security/consoles/ids/crowdsec/decisions/' + decisionId, {
      method: 'DELETE',
    });
    var body = await res.json().catch(function(){ return {}; });
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setConActionStatus(translateError(code), 'error');
      return;
    }
    setConActionStatus(lang === 'ru' ? 'IP ' + ip + ' разбанен.' : 'IP ' + ip + ' unbanned.', 'success');
    await refreshIdsConsole();
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
  // A-58: diagnostic hook (finding F4) — what language the opener runs in.
  console.debug('hranix-lang', 'openNotifications', currentLang());
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
  // A-58: diagnostic hook (finding F4) — the language this render pass used.
  console.debug('hranix-lang', 'renderNotificationsList', currentLang());
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

/* ---------- Настройки → Стек защиты (A-60) ----------
   Экран #view-stack: статус Docker/контейнеров/креденшелов
   (GET /security/stack/status) + кнопка «Развернуть стек защиты»
   (admin-only POST /security/stack/bootstrap) с пошаговым результатом и
   честной подсказкой о перезапуске приложения (Settings читаются при
   старте процесса — без перезапуска коннекторы новых настроек не увидят,
   никакой «магии» перечитывания на лету). */
var lastStackStatus = null;   // последний ответ GET /security/stack/status
var lastStackSteps = null;    // последний ответ POST /security/stack/bootstrap

/* Машиночитаемые значения от сервера переводятся ТОЛЬКО здесь
   (CLAUDE.md «ЛОКАЛИЗАЦИЯ»: сервер отдаёт коды, не текст). */
var STACK_STEP_LABELS = {
  docker: { ru: 'Docker', en: 'Docker' },
  secrets: { ru: 'Секреты стека', en: 'Stack secrets' },
  compose_files: { ru: 'Файлы развертывания', en: 'Deployment files' },
  network: { ru: 'Сеть Docker', en: 'Docker network' },
  filebeat_config: { ru: 'Конфиг Filebeat', en: 'Filebeat config' },
  compose_up: { ru: 'Запуск контейнеров', en: 'Starting containers' },
  crowdsec_credentials: { ru: 'Креденшелы CrowdSec', en: 'CrowdSec credentials' },
  config_env: { ru: 'Настройки приложения', en: 'App settings' },
};
var STACK_STEP_STATUS = {
  ok: { ru: 'готово', en: 'done' },
  missing: { ru: 'отсутствует', en: 'missing' },
  skipped: { ru: 'пропущено', en: 'skipped' },
  port_busy: { ru: 'порты заняты', en: 'ports busy' },
  timeout: { ru: 'превышено время ожидания', en: 'timed out' },
  error: { ru: 'ошибка', en: 'error' },
};
var STACK_DETAIL_CODES = {
  docker_not_installed: {
    ru: 'Docker не найден — установите Docker Desktop, перезапустите приложение и повторите.',
    en: 'Docker was not found — install Docker Desktop, restart the app and try again.',
  },
  docker_daemon_unreachable: {
    ru: 'Docker не отвечает — запустите Docker Desktop и повторите.',
    en: 'Docker is not responding — start Docker Desktop and try again.',
  },
  docker_info_timed_out: {
    ru: 'Docker не отвечает (таймаут) — запустите Docker Desktop и повторите.',
    en: 'Docker is not responding (timeout) — start Docker Desktop and try again.',
  },
};
function translateStackDetail(step, detail){
  if(!detail) return '';
  if(STACK_DETAIL_CODES[detail]) return STACK_DETAIL_CODES[detail][currentLang()];
  // ports_busy: "ports_busy: 55000,3310" и прочие свободные тексты
  // (обрезанный stderr docker) показываются как есть — честно, без выдумки.
  if(detail.indexOf('ports_busy:') === 0){
    var ports = detail.slice('ports_busy:'.length).trim();
    return currentLang() === 'ru'
      ? 'Порты уже заняты другим процессом: ' + ports
      : 'Ports are already in use by another process: ' + ports;
  }
  return detail;
}

function openStackScreen(){
  show('view-stack');
  loadStackStatus();
}
function closeStackScreen(){
  show('view-overview');
  loadOverview();
}

async function loadStackStatus(){
  try{
    var res = await apiFetch('/security/stack/status');
    if(!res.ok) return;
    lastStackStatus = await res.json();
    renderStackStatus();
  } catch(e){ /* network hiccup — экран остаётся в последнем известном состоянии */ }
}

function stackStatusRow(label, valueText, ok){
  var row = document.createElement('div');
  row.className = 'st-row';
  var name = document.createElement('b');
  name.textContent = label;
  var value = document.createElement('span');
  value.textContent = valueText;
  if(ok === true) value.style.color = 'var(--ok, #2e9e5b)';
  if(ok === false) value.style.color = 'var(--danger, #d64545)';
  row.appendChild(name);
  row.appendChild(value);
  return row;
}

function renderStackStatus(){
  var list = document.getElementById('stackStatusList');
  if(!list) return;
  list.textContent = '';
  if(!lastStackStatus){
    list.innerHTML = '<div class="con-empty" data-ru="Статус недоступен" data-en="Status unavailable">Статус недоступен</div>';
    return;
  }
  var lang = currentLang();
  var dockerStatuses = {
    ok: { ru: 'доступен', en: 'available' },
    missing: { ru: 'не найден', en: 'not found' },
  };
  list.appendChild(stackStatusRow(
    lang === 'ru' ? 'Docker' : 'Docker',
    dockerStatuses[lastStackStatus.docker.status][lang],
    lastStackStatus.docker.status === 'ok'
  ));

  var containerStatuses = {
    running: { ru: 'запущены', en: 'running' },
    partial: { ru: 'запущены частично', en: 'partially running' },
    absent: { ru: 'не запущены', en: 'not running' },
  };
  list.appendChild(stackStatusRow(
    lang === 'ru' ? 'Контейнеры (CrowdSec · ClamAV · Wazuh)' : 'Containers (CrowdSec · ClamAV · Wazuh)',
    containerStatuses[lastStackStatus.containers.status][lang],
    lastStackStatus.containers.status === 'running'
  ));

  var credStatuses = {
    ok: { ru: 'настроены', en: 'configured' },
    missing: { ru: 'не настроены', en: 'not configured' },
  };
  list.appendChild(stackStatusRow(
    lang === 'ru' ? 'Креденшелы подключения' : 'Connection credentials',
    credStatuses[lastStackStatus.credentials.status][lang],
    lastStackStatus.credentials.status === 'ok'
  ));
}

async function handleStackBootstrap(){
  var btn = document.getElementById('stackBootstrapBtn');
  var statusBox = document.getElementById('stackBootstrapStatus');
  var stepsList = document.getElementById('stackStepsList');
  var restartHint = document.getElementById('stackRestartHint');
  var confirmed = window.confirm(currentLang() === 'ru'
    ? 'Развернуть стек защиты? Скачаются образы Docker (CrowdSec, ClamAV, Wazuh — может занять несколько минут) и будут созданы настройки подключения.'
    : 'Deploy the security stack? Docker images will be downloaded (CrowdSec, ClamAV, Wazuh — may take a few minutes) and connection settings will be created.');
  if(!confirmed) return;

  btn.disabled = true;
  statusBox.hidden = true;
  stepsList.hidden = true;
  restartHint.hidden = true;
  try{
    var res = await apiFetch('/security/stack/bootstrap', { method: 'POST' });
    var body = await res.json().catch(function(){ return {}; });
    if(res.status === 403){
      setStackBootstrapStatus(translateError('insufficient_role'), 'warn');
      return;
    }
    if(!res.ok){
      var code = (body.detail && body.detail.error) || 'unknown_error';
      setStackBootstrapStatus(translateError(code), 'warn');
      return;
    }
    lastStackSteps = body;
    renderStackSteps();
    var allOk = body.status === 'ok';
    if(allOk){
      setStackBootstrapStatus(currentLang() === 'ru'
        ? 'Стек развернут.'
        : 'The stack has been deployed.', 'ok');
      restartHint.textContent = currentLang() === 'ru'
        ? 'Стек поднят. Перезапустите приложение, чтобы коннекторы прочитали новые настройки.'
        : 'The stack is up. Restart the application so the connectors pick up the new settings.';
      restartHint.hidden = false;
    } else {
      var failed = (body.steps || []).filter(function(s){ return s.status !== 'ok' && s.status !== 'skipped'; });
      var firstFailed = failed.length ? failed[0] : null;
      var reason = firstFailed ? translateStackDetail(firstFailed.step, firstFailed.detail) : '';
      setStackBootstrapStatus(
        (currentLang() === 'ru' ? 'Развертывание не завершено. ' : 'Deployment did not complete. ') + reason,
        'warn');
    }
    loadStackStatus();
  } catch(e){
    setStackBootstrapStatus(translateError('network_error'), 'warn');
  } finally {
    btn.disabled = false;
  }
}

function setStackBootstrapStatus(text, kind){
  var box = document.getElementById('stackBootstrapStatus');
  if(!box) return;
  box.hidden = !text;
  box.className = 'con-status' + (kind ? ' ' + kind : '');
  box.textContent = text;
}

function renderStackSteps(){
  var list = document.getElementById('stackStepsList');
  if(!list || !lastStackSteps) return;
  list.textContent = '';
  var steps = lastStackSteps.steps || [];
  if(!steps.length){ list.hidden = true; return; }
  list.hidden = false;
  var lang = currentLang();
  steps.forEach(function(step){
    var item = document.createElement('div');
    item.className = 'st-row';
    var name = document.createElement('b');
    name.textContent = (STACK_STEP_LABELS[step.step] || { ru: step.step, en: step.step })[lang];
    var value = document.createElement('span');
    var statusText = (STACK_STEP_STATUS[step.status] || { ru: step.status, en: step.status })[lang];
    if(step.status !== 'ok' && step.status !== 'skipped'){
      var detail = translateStackDetail(step.step, step.detail);
      if(detail) statusText += ' — ' + detail;
    }
    value.textContent = statusText;
    value.style.color = step.status === 'ok' ? 'var(--ok, #2e9e5b)'
      : (step.status === 'skipped' ? 'inherit' : 'var(--danger, #d64545)');
    item.appendChild(name);
    item.appendChild(value);
    list.appendChild(item);
  });
}

/* ---------- инициализация ---------- */
// A-37: Escape closes the port-detail modal — the same "Cancel"-equivalent
// affordance the modal's own × button/backdrop click already give, just
// via the keyboard. A no-op whenever the modal is not open (closePortModal
// itself is idempotent — hiding an already-hidden overlay/nulling an
// already-null portModalItem is harmless).
// A-43: same affordance for the scenario-thresholds modal — found missing
// during architect review (the port modal got it in A-37, this one didn't
// carry it over), fixed the same way: idempotent, harmless when not open.
// A-53: same affordance for the connection-detail modal, same idempotent
// "harmless when not open" reasoning.
document.addEventListener('keydown', function(e){
  if(e.key === 'Escape'){
    closePortModal();
    closeScenarioThresholdsModal();
    closeConnectionModal();
  }
});

document.addEventListener('DOMContentLoaded', function(){
  applyTheme(currentTheme());
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
