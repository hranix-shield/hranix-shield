"""A-63-5 (расширение, живой фидбек владельца 2026-09-21): «нет индикации
процесса обновления и ничего не понятно» — длительные elevated-кнопки
(«⬇️ Обновить базы», «Проверить обновления», сканы, блокировки…) не давали
никакого отклика во время работы.

Фикс: `attachButtonBusyHandler` оборачивает каждый реальный handler — на
время выполнения промиса кнопка показывает busy-надпись (своя у действия:
«Обновляем базы…», «Проверяем обновления…», …, общий фолбэк
«Выполняется…») и заблокирована от двойных кликов; по завершении (успех
или ошибка) надпись восстанавливается. Якорь — Node vm против реального
app.js: busy-текст/дизейбл во время работы, восстановление после, защита
от двойного клика, восстановление после исключения.
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

function makeButton(){
  var el = {
    hidden: false,
    textContent: '',
    title: '',
    style: {},
    className: '',
    disabled: false,
    isConnected: true,
    _attr: {},
    classList: {
      _set: {},
      toggle: function(c, on){ this._set[c] = !!on; },
      add: function(c){ this._set[c] = true; },
      remove: function(c){ this._set[c] = false; },
      has: function(c){ return !!this._set[c]; },
    },
    dataset: {},
    appendChild: function(){},
    setAttribute: function(name, value){ el._attr[name] = value; },
    onclick: null,
  };
  return el;
}

var context = {
  console: console,
  navigator: { platform: 'Win32', userAgent: 'Win32' },
  localStorage: { getItem: function(){ return null; }, setItem: function(){}, removeItem: function(){} },
  document: {
    getElementById: function(){ return makeButton(); },
    createElement: function(){ return makeButton(); },
    createTextNode: function(t){ var n = makeButton(); n.textContent = String(t); return n; },
    querySelector: function(){ return null; },
    querySelectorAll: function(){ return []; },
    addEventListener: function(){},
    documentElement: {},
    body: makeButton(),
  },
  getComputedStyle: function(){ return { getPropertyValue: function(){ return ''; } }; },
  window: { devicePixelRatio: 1, confirm: function(){ return false; } },
  fetch: function(){ return Promise.resolve({ ok: false, status: 500, json: function(){ return Promise.resolve({}); } }); },
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'app.js' });
globalThis.__context = context;
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
def test_action_button_shows_busy_label_while_handler_runs_and_restores_after():
    js = r"""
    (async () => {
    var ctx = globalThis.__context;
    var btn = ctx.document.createElement('button');
    btn.textContent = '⬇️ Обновить базы';
    var calls = 0;

    var resolveHandler;
    var handler = function(){ calls += 1; return new Promise(function(r){ resolveHandler = r; }); };
    ctx.attachButtonBusyHandler(btn, handler, 'Обновляем базы…');

    btn.onclick();                       // клик оператора
    var during = {
      text: btn.textContent,
      disabled: btn.disabled,
      busyClass: btn.classList.has('btn-busy'),
      calls: calls,
    };

    // Двойной клик во время работы — не проходит (disabled-защита).
    btn.onclick();
    var doubleClickCalls = calls;

    resolveHandler();                    // действие завершилось
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    var after = {
      text: btn.textContent,
      disabled: btn.disabled,
      busyClass: btn.classList.has('btn-busy'),
      calls: calls,
    };
    return { during: during, doubleClickCalls: doubleClickCalls, after: after };
    })().then(function(v){ console.log(JSON.stringify(v)); });
    """
    out = _run(js)

    assert out["during"]["text"] == "Обновляем базы…"
    assert out["during"]["disabled"] is True
    assert out["during"]["busyClass"] is True
    assert out["doubleClickCalls"] == 1              # двойной клик не прошёл
    assert out["after"]["text"] == "⬇️ Обновить базы"   # надпись восстановлена
    assert out["after"]["disabled"] is False
    assert out["after"]["busyClass"] is False
    assert out["after"]["calls"] == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_action_button_restores_when_handler_throws_synchronously():
    """Синхронный throw в handler'е не должен оставлять кнопку навсегда
    busy — обёртка восстанавливает и прокидывает исключение дальше."""
    js = r"""
    (async () => {
    var ctx = globalThis.__context;
    var btn = ctx.document.createElement('button');
    btn.textContent = 'Правила фаервола';
    var caught = null;

    ctx.attachButtonBusyHandler(btn, function(){ throw new TypeError('boom'); }, 'Читаем правила…');
    try { btn.onclick(); } catch(e) { caught = String(e.message); }
    await Promise.resolve();

    return { caught: caught, text: btn.textContent, disabled: btn.disabled };
    })().then(function(v){ console.log(JSON.stringify(v)); });
    """
    out = _run(js)

    assert out["caught"] == "boom"
    assert out["text"] == "Правила фаервола"
    assert out["disabled"] is False
