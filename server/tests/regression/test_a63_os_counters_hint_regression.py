"""A-63-7 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): владелец видит «OS counters: не подключён» без объяснений, а
generic-тултип «задайте параметры подключения в .env» вводит в заблуждение.

Два факта, которые тултип обязан честно проговаривать (см. app.js's
osCountersHint docstring и traffic_counters.py's own Windows-обоснование):

  1. os_counters НЕ входит в «Стек защиты» по дизайну — это не сервис и не
     контейнер, разворачивать нечего: коннектор читает штатные средства ОС.
  2. На Windows надёжного не-административного способа посчитать per-process
     трафик НЕТ вообще — на машине владельца этот источник честно
     `not_configured` навсегда, никаких .env-ключей не существует.

Якоря (Node vm против реального app.js): текст подсказки называет оба
факта и не обещает несуществующих .env-настроек; Windows-детект
переключает формулировку; баннер консоли получает подсказку как `title`
ровно когда os_counters = not_configured (и не получает при ok).
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_APP_JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "assets" / "app.js"

# Тот же минимальный фейк-DOM, что в test_a63_map_click_regression.py,
# плюс navigator (osCountersHint читает navigator.platform) и Language.
_HARNESS = r"""
const fs = require('fs');
const code = fs.readFileSync(process.argv[1], 'utf8');

function makeBox(){
  var el = {
    hidden: true,
    textContent: '',
    title: '',
    style: { setProperty: function(){}, removeProperty: function(){} },
    className: '',
    children: [],
    classList: { toggle: function(){}, add: function(){}, remove: function(){} },
    // dataset: renderConsole читает произвольные data-* ключи (dataset.ru /
    // dataset.en) — отдаём пустую строку на любой ключ.
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

var conError = makeBox();

var context = {
  console: console,
  navigator: { platform: process.argv[2], userAgent: process.argv[2] },
  localStorage: { _store: {}, getItem: function(k){ return context.localStorage._store[k] || null; }, setItem: function(k,v){ context.localStorage._store[k] = String(v); }, removeItem: function(){} },
  document: {
    getElementById: function(id){ return id === 'conError' ? conError : makeCanvas(); },
    createElement: function(){ return makeBox(); },
    createTextNode: function(t){ var n = makeBox(); n.textContent = String(t); return n; },
    querySelector: function(){ return null; },
    addEventListener: function(){},
    documentElement: {},
  },
  getComputedStyle: function(){ return { getPropertyValue: function(){ return ''; } }; },
  window: { devicePixelRatio: 1, confirm: function(){ return false; } },
  fetch: function(){ return Promise.resolve({ ok: false, status: 500, json: function(){ return Promise.resolve({}); } }); },
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'app.js' });
context.__testConError = function(){ return conError; };
globalThis.__context = context;
globalThis.__conError = conError;
"""


def _run(js: str, platform: str = "Win32") -> dict:
    result = subprocess.run(
        ["node", "-e", _HARNESS + "\n" + js, str(_APP_JS_PATH), platform],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_os_counters_hint_names_both_honest_facts_on_windows():
    """Windows-подсказка: что это, почему нет в «Стеке защиты» (не сервис и
    не контейнер), почему на Windows всегда «—» (нет не-административного
    способа). Не упоминает .env-настройки — их не существует."""
    js = r"""
    var out = {};
    out.ru = ctx.osCountersHint();
    ctx.localStorage.setItem('hranix-lang', 'en');
    out.en = ctx.osCountersHint();
    console.log(JSON.stringify(out));
    """
    js = js.replace("ctx.", "globalThis.__context.")
    out = _run(js, "Win32")

    assert "Отправлено/Получено" in out["ru"]
    assert "не сервис и не контейнер" in out["ru"]
    assert "Стеке защиты" in out["ru"]
    assert "без прав администратора" in out["ru"]
    # Честность: никаких обещаний .env-ключей, которых не существует.
    assert ".env" not in out["ru"]
    assert "задайте параметры" not in out["ru"]

    assert "Sent/Received" in out["en"]
    assert "not a service or a container" in out["en"]
    assert "non-admin" in out["en"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_os_counters_hint_switches_wording_for_non_windows_platforms():
    """macOS/Linux: работает из коробки — формулировка другая (нет
    «на Windows всегда —»), но «не контейнер» остаётся."""
    js = r"""
    console.log(JSON.stringify({ ru: ctx.osCountersHint() }));
    """
    js = js.replace("ctx.", "globalThis.__context.")
    out = _run(js, "MacIntel")

    assert "не сервис и не контейнер" in out["ru"]
    assert "из коробки" in out["ru"]
    assert "без прав администратора нет" not in out["ru"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_console_banner_carries_the_hint_only_for_os_counters_not_configured():
    """Баннер консоли «Сеть»: при os_counters not_configured — title с
    подсказкой; при ok — title пуст; чужие источники подсказку не дают."""
    js = r"""
    var ctx = globalThis.__context;
    ctx.lastConsoleId = 'network';
    var out = {};

    ctx.lastConsoleData = { connector: null, connectors: { os_counters: { status: 'not_configured' } }, enabled: true, network_profile: null, allowlist: null };
    ctx.renderConsole();
    out.notConfiguredTitle = ctx.__testConError().title;
    out.notConfiguredText = ctx.__testConError().textContent;
    out.notConfiguredHidden = ctx.__testConError().hidden;

    ctx.lastConsoleData = { connector: null, connectors: { os_counters: { status: 'ok' } }, enabled: true, network_profile: null, allowlist: null };
    ctx.renderConsole();
    out.okTitle = ctx.__testConError().title;
    out.okHidden = ctx.__testConError().hidden;

    console.log(JSON.stringify(out));
    """
    out = _run(js, "Win32")

    assert "OS counters: " in out["notConfiguredText"]
    assert "не сервис и не контейнер" in out["notConfiguredTitle"]
    assert out["notConfiguredHidden"] is False
    assert out["okTitle"] == ""
    assert out["okHidden"] is True
