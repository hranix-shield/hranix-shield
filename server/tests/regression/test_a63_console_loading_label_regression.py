"""A-63-5 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): «висит информация от старого» при смене разделов.

Механика: первый fetch консоли с живым стеком занимает секунды (реальные
osquery/Wazuh вызовы), и всё это время `openConsole` показывал заголовок и
блоки данных ПРЕДЫДУЩЕЙ консоли — шапка (`conTitle`/`conEngine`) обновлялась
только в `renderConsole()`, уже после прихода данных.

Фикс: `openConsole` немедленно ставит заголовок новой консоли из
CONSOLE_META, показывает пульсирующую метку «Обновляется…» (`#conUpdating`)
и прячет блоки данных прошлой консоли (список/график/карту); метку гасит
`renderConsole()` (единственная точка, куда приходит ЛЮБОЙ успешный путь —
первая загрузка, кнопка обновления, авто-poll) и обе error-ветки
`openConsole`. A-63-3's in-flight guard уже не даёт фетчам наслаиваться —
нового refetch-шторма этот индикатор не создаёт (он чисто визуальный).

Якорь — Node vm против реального app.js: состояние экрана сразу после
открытия консоли (до прихода данных), после успешной загрузки и после
HTTP-ошибки.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_APP_JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "assets" / "app.js"

_HARNESS = r"""
const fs = require('fs');
const code = fs.readFileSync(process.argv[1], 'utf8');

function makeBox(){
  var el = {
    hidden: true,
    textContent: '',
    title: '',
    style: {},
    className: '',
    id: '',
    children: [],
    classList: { toggle: function(){}, add: function(){}, remove: function(){} },
    dataset: new Proxy({}, { get: function(){ return ''; }, set: function(){ return true; } }),
    appendChild: function(c){ el.children.push(c); return c; },
    setAttribute: function(name, value){ el['_attr_' + name] = value; },
  };
  return el;
}

function makeCanvas(){
  var el = makeBox();
  el.clientWidth = 320; el.clientHeight = 220;
  var ctxProxy = new Proxy({}, {
    get: function(t, p){ return p === 'canvas' ? null : function(){ return undefined; }; },
    set: function(){ return true; },
  });
  el.getContext = function(){ return ctxProxy; };
  el.getBoundingClientRect = function(){ return { left: 0, top: 0, width: 320, height: 220 }; };
  return el;
}

var boxes = {};
var ids = ['conIcon', 'conTitle', 'conEngine', 'conUpdating', 'conError',
           'conListSection', 'conChartCard', 'conMapCard'];
ids.forEach(function(id){ boxes[id] = makeBox(); });

var context = {
  console: console,
  navigator: { platform: 'Win32', userAgent: 'Win32' },
  localStorage: { _store: {}, getItem: function(k){ return context.localStorage._store[k] || null; }, setItem: function(k,v){ context.localStorage._store[k] = String(v); }, removeItem: function(){} },
  document: {
    getElementById: function(id){ return boxes[id] || makeCanvas(); },
    createElement: function(){ return makeBox(); },
    createTextNode: function(t){ var n = makeBox(); n.textContent = String(t); return n; },
    querySelector: function(){ return null; },
    querySelectorAll: function(){ return []; },
    addEventListener: function(){},
    documentElement: {},
  },
  getComputedStyle: function(){ return { getPropertyValue: function(){ return ''; } }; },
  window: { devicePixelRatio: 1, confirm: function(){ return false; } },
  fetch: function(){ return Promise.resolve({ ok: false, status: 500, json: function(){ return Promise.resolve({}); } }); },
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'app.js' });
context.__boxes = boxes;
globalThis.__context = context;
globalThis.__boxes = boxes;
"""


def _run(js: str) -> dict:
    result = subprocess.run(
        ["node", "-e", _HARNESS + "\n" + js, str(_APP_JS_PATH)],
        capture_output=True,
        # node всегда пишет stdout в UTF-8; без явной кодировки Python
        # декодирует локалью (на CI-раннере cp1252) и русский текст мётся.
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    assert result.stdout, f"node produced no stdout: rc={result.returncode}, stderr={result.stderr!r}"
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_open_console_shows_updating_label_and_hides_stale_blocks_immediately():
    """Сразу после openConsole (fetch ещё висит): заголовок — уже НОВАЯ
    консоль, «Обновляется…» виден, блоки данных прошлой консоли скрыты,
    движок — «…»."""
    js = r"""
    (async () => {
    var ctx = globalThis.__context, boxes = globalThis.__boxes;
    // Имитируем «до этого была открыта logs»: старый заголовок/движок.
    boxes.conTitle.textContent = 'Журналы ОС';
    boxes.conEngine.textContent = 'Wazuh';

    var pendingResolve = null;
    ctx.fetch = function(){ return new Promise(function(r){ pendingResolve = r; }); };
    ctx.CONSOLE_ROUTES = { network: '/security/consoles/network' };

    var opening = ctx.openConsole('network');
    // Синхронная часть openConsole выполнена до первого await — состояние
    // экрана можно проверять, пока fetch ещё висит.
    var duringFlight = {
      title: boxes.conTitle.textContent,
      icon: boxes.conIcon.textContent,
      engine: boxes.conEngine.textContent,
      updatingHidden: boxes.conUpdating.hidden,
      listHidden: boxes.conListSection.hidden,
      chartHidden: boxes.conChartCard.hidden,
      mapHidden: boxes.conMapCard.hidden,
    };

    pendingResolve({
      ok: true, status: 200,
      json: function(){
        return Promise.resolve({
          id: 'network', status: 'ok', enabled: true,
          engine: ['osquery'], connector: { status: 'ok' },
          connectors: {}, metrics: {}, chart: {}, connections: [],
        });
      },
    });
    await opening;
    var afterLoad = {
      title: boxes.conTitle.textContent,
      engine: boxes.conEngine.textContent,
      updatingHidden: boxes.conUpdating.hidden,
    };

    return { duringFlight: duringFlight, afterLoad: afterLoad };
    })().then(function(v){ console.log(JSON.stringify(v)); });
    """
    out = _run(js)

    assert out["duringFlight"]["title"] == "Сеть"          # заголовок сменён СРАЗУ
    assert out["duringFlight"]["engine"] == "…"
    assert out["duringFlight"]["updatingHidden"] is False  # метка «Обновляется…» видна
    assert out["duringFlight"]["listHidden"] is True       # старые блоки скрыты
    assert out["duringFlight"]["chartHidden"] is True
    assert out["duringFlight"]["mapHidden"] is True

    assert out["afterLoad"]["updatingHidden"] is True      # данные пришли — метка погашена
    assert out["afterLoad"]["engine"] == "Osquery"         # настоящий движок отрисован


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_open_console_stops_the_label_on_http_error_and_network_failure():
    """Обе error-ветки openConsole (не-ok ответ и сетевой сбой) гасят
    «Обновляется…» — метка не может остаться висеть навсегда."""
    js = r"""
    (async () => {
    var ctx = globalThis.__context, boxes = globalThis.__boxes;
    var out = {};

    ctx.CONSOLE_ROUTES = { network: '/security/consoles/network' };

    // Ветка «не-ok»: 503 с машчитаемым кодом.
    ctx.fetch = function(){
      return Promise.resolve({
        ok: false, status: 503,
        json: function(){ return Promise.resolve({ detail: { error: 'clamav_not_configured' } }); },
      });
    };
    await ctx.openConsole('network');
    out.httpErrorUpdatingHidden = boxes.conUpdating.hidden;
    out.httpErrorBannerHidden = boxes.conError.hidden;

    // Ветка сетевого сбоя: fetch бросает.
    ctx.fetch = function(){ return Promise.reject(new TypeError('failed to fetch')); };
    await ctx.openConsole('network');
    out.networkErrorUpdatingHidden = boxes.conUpdating.hidden;

    return out;
    })().then(function(v){ console.log(JSON.stringify(v)); });
    """
    out = _run(js)

    assert out["httpErrorUpdatingHidden"] is True
    assert out["httpErrorBannerHidden"] is False           # ошибка показана вместо данных
    assert out["networkErrorUpdatingHidden"] is True
