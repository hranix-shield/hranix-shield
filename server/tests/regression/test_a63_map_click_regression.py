"""A-63-3 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): «клик по узлу карты — и всё исчезло с карты»; в воспроизведении
архитектора приложение целиком улетало на экран логина.

Живой прогон против dev-сервера с реальными соединениями (браузер агента,
2026-09-21) зафиксировал фактическую механику:

  1. Клик по узлу canvas-карты БЕЗВРЕДЕН по построению: у `#conMapCanvas`
     вообще НЕТ click-обработчика (index.html вешает только `onmousemove`/
     `onmouseleave`), а оба хит-теста (`handleConMapMouseMove`/
     `handleConMapMouseLeave`) только пишут `canvas.title`. Живо подтверждено:
     клик/двойной клик по узлу — тултип узла («US: 98 соединений»),
     аутентификация не меняется, карта не очищается, JS-ошибок нет.
  2. «Всё исчезло» — это фоновая перерисовка 5-секундного poll'а: ответ с
     честным `connector.status: "unreachable"` несёт `connections: []`, и
     `renderConsole()` перерисовывал карту ПОЛНОСТЬЮ ПУСТОЙ до следующего
     успешного poll'а. Плюс сам poll наслаивался: каждый 5-секундный тик
     стрелял новый запрос, пока предыдущий висел, параллельные osqueryi
     душили друг друга (живой лог: «timed out after 15.0s»).

Фикс: `renderConnectionsMap` при недоступном коннекторе НЕ перерисовывает
карту пустотой — рисует последнюю успешную выборку (`lastGoodMapConnections`)
с честной пометкой в note; `refreshNetworkConsole` пропускает тик, пока
предыдущий запрос в полёте (`networkRefreshInFlight`).

Якоря в этом файле: (а) у canvas карты нет клик-обработчика в index.html и
app.js — клик физически нечему менять; (б) `handleConMapMouseMove`/
`handleConMapMouseLeave` (единственные обработчики canvas) не бросают, не
трогают localStorage/auth, не сбрасывают `lastConsoleData`, тултип узла —
штатный; (в) unreachable-перерисовка не опустошает карту. Всё — через
Node `vm` против реального app.js, same technique
test_a34_network_table_regression.py / test_a41_network_map_regression.py.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

# tests/regression/test_a63_....py -> server/app/static/{assets/app.js, index.html}
_APP_JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "assets" / "app.js"
_INDEX_HTML_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "index.html"

# Общий vm-харнесс: реальный app.js + минимальный фейк-DOM (canvas с 2d-
# прокси, localStorage-шпион, fetch-шпион). Никаких реальных сетевых
# вызовов; showLogin НЕ вызывается — шпион на localStorage.removeItem и
# fetch доказывает, что обработчики карты не трогают аутентификацию.
_HARNESS = r"""
const vm = require('vm');
const fs = require('fs');
const code = fs.readFileSync(process.argv[1], 'utf8');

function makeCtxProxy(){
  return new Proxy({}, {
    get: function(target, prop){
      if(prop === 'canvas') return null;
      return function(){ return undefined; };
    },
    set: function(){ return true; },
  });
}

function makeCanvas(){
  var el = {
    title: '',
    ariaLabel: '',
    width: 0,
    height: 0,
    clientWidth: 726,
    clientHeight: 360,
    getContext: function(){ return makeCtxProxy(); },
    getBoundingClientRect: function(){ return { left: 109, top: 522, width: 726, height: 360 }; },
    setAttribute: function(name, value){ el['_attr_' + name] = value; },
  };
  return el;
}

function makeBox(){
  var el = {
    hidden: true,
    textContent: '',
    style: {},
    children: [],
    appendChild: function(c){ el.children.push(c); return c; },
    setAttribute: function(name, value){ el['_attr_' + name] = value; },
  };
  return el;
}

var calls = { removeItem: [], fetch: [] };
var canvas = makeCanvas();
var noteBox = makeBox();
var mapCard = makeBox();

var context = {
  console: console,
  // Фейки окружения app.js (см. настоящий index.html: только mousemove/
  // mouseleave, никакого onclick).
  window: { devicePixelRatio: 1, confirm: function(){ return false; } },
  document: {
    createElement: function(){ return makeBox(); },
    createTextNode: function(t){ var n = makeBox(); n.textContent = String(t); return n; },
    getElementById: function(id){
      if(id === 'conMapCanvas') return canvas;
      if(id === 'conMapNote') return noteBox;
      if(id === 'conMapCard') return mapCard;
      return makeBox();
    },
    querySelector: function(){ return null; },
    addEventListener: function(){},
    documentElement: {},
  },
  getComputedStyle: function(){ return { getPropertyValue: function(){ return ''; } }; },
  localStorage: {
    _store: { token: 'sentinel' },
    getItem: function(k){ return (context.localStorage._store[k] !== undefined) ? context.localStorage._store[k] : null; },
    setItem: function(k, v){ context.localStorage._store[k] = String(v); },
    removeItem: function(k){ calls.removeItem.push(k); delete context.localStorage._store[k]; },
  },
  fetch: function(){ calls.fetch.push(Array.prototype.slice.call(arguments)); return Promise.resolve({ ok: false, status: 500, json: function(){ return Promise.resolve({}); } }); },
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'app.js' });
context.document.getElementById = context.document.getElementById;
globalThis.__context = context;
globalThis.__calls = calls;
globalThis.__canvas = canvas;
globalThis.__noteBox = noteBox;
globalThis.__mapCard = mapCard;
"""


def _run_harness(js: str) -> dict:
    result = subprocess.run(
        ["node", "-e", _HARNESS + "\n" + js, str(_APP_JS_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_map_canvas_has_no_click_handler_at_all():
    """Клик по узлу физически нечему обрабатывать: index.html вешает на
    `#conMapCanvas` только `onmousemove`/`onmouseleave`; в app.js нет ни
    одного `onclick`/`addEventListener('click')` на canvas карты. Это и
    есть статический корень «клик по узлу не может менять аутентификацию»:
    единственные обработчики — хит-тесты тултипа."""
    html = _INDEX_HTML_PATH.read_text(encoding="utf-8")
    html_lines = html.splitlines()
    canvas_idx = next(i for i, line in enumerate(html_lines) if 'id="conMapCanvas"' in line)
    # Тег многострочный: атрибуты обработчиков — на следующей строке.
    canvas_block = html_lines[canvas_idx] + "\n" + html_lines[canvas_idx + 1]
    assert 'onmousemove="handleConMapMouseMove(event)"' in canvas_block
    assert 'onmouseleave="handleConMapMouseLeave()"' in canvas_block
    assert "onclick" not in canvas_block
    assert "ondblclick" not in canvas_block

    source = _APP_JS_PATH.read_text(encoding="utf-8")
    assert "conMapCanvas').onclick" not in source
    assert "conMapCanvas\").onclick" not in source
    # addEventListener в файле есть ровно два (keydown/DOMContentLoaded, оба
    # на document) — клик-слушателей на карту не появилось.
    for line in source.splitlines():
        if "addEventListener" in line:
            assert "'click'" not in line and '"click"' not in line


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_map_hit_test_tooltip_works_and_never_touches_auth_or_console_data():
    """Единственные обработчики canvas — тултип-хит-тесты. Прогон реального
    кода: узел под курсором — точный тултип; мимо узлов — сводный summary;
    пустая карта — no-op без исключений. НИ ОДИН из вызовов не трогает
    localStorage.removeItem (т.е. не может разлогинить), не делает fetch и
    не сбрасывает sentinel `lastConsoleData` («не очищает карту»)."""
    js = r"""
    var ctx = globalThis.__context, calls = globalThis.__calls, canvas = globalThis.__canvas;
    ctx.lastMapPoints = [
      { x: 170, y: 106, radius: 14, country: 'US', count: 98, suspicious: false },
      { x: 572, y: 177, radius: 11, country: 'SG', count: 8, suspicious: true },
    ];
    ctx.lastMapSummaryTitle = 'SUMMARY';
    ctx.lastConsoleData = { __sentinel: true };

    var out = { steps: [] };

    // Клик по узлу US: mousemove в его центр (viewport = canvas-координаты
    // + rect.left/top в реальном браузере; фейк-rect вернёт (109, 522)).
    ctx.handleConMapMouseMove({ clientX: 109 + 170, clientY: 522 + 106 });
    out.steps.push({ after: 'hit US', title: canvas.title });

    // Уход с карты.
    ctx.handleConMapMouseLeave();
    out.steps.push({ after: 'leave', title: canvas.title });

    // Клик по узлу SG (подозрительный — суффикс).
    ctx.handleConMapMouseMove({ clientX: 109 + 572, clientY: 522 + 177 });
    out.steps.push({ after: 'hit SG', title: canvas.title });

    // Клик мимо узлов — сводный title.
    ctx.handleConMapMouseMove({ clientX: 109 + 5, clientY: 522 + 5 });
    out.steps.push({ after: 'miss', title: canvas.title });

    // Пустая карта (после showLogin-подобного сброса) — no-op.
    ctx.lastMapPoints = [];
    ctx.handleConMapMouseMove({ clientX: 279, clientY: 628 });
    out.steps.push({ after: 'empty', title: canvas.title });

    out.removeCalls = calls.removeItem;
    out.fetchCalls = calls.fetch.length;
    out.sentinelIntact = ctx.lastConsoleData && ctx.lastConsoleData.__sentinel === true;
    console.log(JSON.stringify(out));
    """
    out = _run_harness(js)

    assert out["steps"][0] == {"after": "hit US", "title": "US: 98 соединений"}
    assert out["steps"][1] == {"after": "leave", "title": "SUMMARY"}
    # Подозрительный узел помечается суффиксом — штатный тултип узла.
    assert out["steps"][2] == {"after": "hit SG", "title": "SG: 8 соединений — подозрительно"}
    assert out["steps"][3] == {"after": "miss", "title": "SUMMARY"}
    assert out["steps"][4]["after"] == "empty"
    assert out["steps"][4]["title"] == "SUMMARY"  # no-op, title не тронут
    # Аутентификация и данные не тронуты ни одним вызовом.
    assert out["removeCalls"] == []
    assert out["fetchCalls"] == 0
    assert out["sentinelIntact"] is True


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_unreachable_repoll_does_not_blank_the_map():
    """Корень «всё исчезло с карты»: poll с честным `unreachable` (пустые
    connections) перерисовывал карту пустотой. После фикса: карта рисуется
    из последней успешной выборки, note честно объясняет, а при возврате
    коннектора картина обновляется из свежих данных. Здоровый пустой ответ
    (коннектор ok, просто нечего показывать) по-прежнему рисует пустую
    карту — «мы знаем, что пусто», не «мы не знаем»."""
    js = r"""
    var ctx = globalThis.__context, calls = globalThis.__calls, canvas = globalThis.__canvas;
    var noteBox = globalThis.__noteBox;
    ctx.lastConsoleData = { __sentinel: true };

    // 1) Успешная выборка — карта наполняется, snapshot запоминается.
    var good = [
      { country: 'US', lat: 37.09, lon: -95.71, count: 3, suspicious: false },
      { country: 'SG', lat: 1.35, lon: 103.82, count: 2, suspicious: false },
    ];
    ctx.renderConnectionsMap(good, 'ok', 'ok');
    var afterGood = { points: ctx.lastMapPoints.length, noteHidden: noteBox.hidden, noteText: noteBox.textContent };
    var storedGood = JSON.parse(JSON.stringify(ctx.lastGoodMapConnections));

    // 2) Живой сценарий: следующий poll — unreachable + connections: [].
    ctx.renderConnectionsMap([], 'ok', 'unreachable');
    var afterUnreachable = {
      points: ctx.lastMapPoints.length,
      noteHidden: noteBox.hidden,
      noteText: noteBox.textContent,
      cardHidden: globalThis.__mapCard.hidden,
    };

    // 3) Коннектор вернулся — картина обновляется свежими данными.
    var fresh = [{ country: 'DE', lat: 51.0, lon: 10.0, count: 1, suspicious: false }];
    ctx.renderConnectionsMap(fresh, 'ok', 'ok');
    var afterRecovery = { points: ctx.lastMapPoints.length, noteHidden: noteBox.hidden, countries: ctx.lastMapPoints.map(function(p){ return p.country; }) };

    // 4) Здоровый пустой ответ: пустая карта — это честные данные.
    ctx.renderConnectionsMap([], 'ok', 'ok');
    var afterHealthyEmpty = { points: ctx.lastMapPoints.length, noteHidden: noteBox.hidden };

    console.log(JSON.stringify({
      afterGood: afterGood, storedGood: storedGood,
      afterUnreachable: afterUnreachable, afterRecovery: afterRecovery,
      afterHealthyEmpty: afterHealthyEmpty,
    }));
    """
    out = _run_harness(js)

    # 1) Успешная выборка: 2 точки, note скрыт (GeoIP ok), snapshot сохранён.
    assert out["afterGood"]["points"] == 2
    assert out["afterGood"]["noteHidden"] is True
    assert [row["country"] for row in out["storedGood"]] == ["US", "SG"]

    # 2) unreachable + пусто: карта НЕ опустела (последняя валидная выборка),
    #    note с честным объяснением, карточка карты видима.
    assert out["afterUnreachable"]["points"] == 2
    assert out["afterUnreachable"]["noteHidden"] is False
    assert "временно недоступен" in out["afterUnreachable"]["noteText"]
    assert "последнюю успешную выборку" in out["afterUnreachable"]["noteText"]
    assert out["afterUnreachable"]["cardHidden"] is False

    # 3) Восстановление: свежие данные, note снова скрыт.
    assert out["afterRecovery"]["points"] == 1
    assert out["afterRecovery"]["countries"] == ["DE"]
    assert out["afterRecovery"]["noteHidden"] is True

    # 4) Здоровое «пусто» — пустая карта, без note (это реальные данные).
    assert out["afterHealthyEmpty"]["points"] == 0
    assert out["afterHealthyEmpty"]["noteHidden"] is True


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_network_poll_skips_a_tick_while_previous_request_is_in_flight():
    """A-63-3: параллельные osqueryi-шторма больше не создаются клиентом —
    `refreshNetworkConsole` пропускает тик, пока предыдущий запрос в полёте
    (`networkRefreshInFlight`); флаг сбрасывается и при ошибке, и при
    не-ok ответе (finally/early-return), так что poll не «умирает» навсегда."""
    js = r"""
    var ctx = globalThis.__context, calls = globalThis.__calls;
    var pendingResolve = null;
    ctx.fetch = function(){
      calls.fetch.push('network');
      return new Promise(function(resolve){
        pendingResolve = resolve;
      });
    };
    ctx.lastConsoleId = 'network';
    ctx.lastConsoleData = { __sentinel: true };
    ctx.CONSOLE_ROUTES = { network: '/security/consoles/network' };
    ctx.stopNetworkPolling = function(){};
    ctx.renderConsole = function(){};

    var p1 = ctx.refreshNetworkConsole();  // запрос №1 — висит (pendingResolve ждёт)
    var p2 = ctx.refreshNetworkConsole();  // тик во время полёта — должен быть ПРОПУЩЕН
    await Promise.resolve(); await Promise.resolve();
    var duringFlight = calls.fetch.length;

    pendingResolve({ ok: true, status: 200, json: function(){ return Promise.resolve({ connector: { status: 'ok' }, connections: [] }); } });
    await p1; await p2;
    var afterDone = calls.fetch.length;

    // Следующий тик после завершения — снова идёт в сеть (мок с
    // немедленным ответом: pending-промис не держит event loop node).
    ctx.fetch = function(){
      calls.fetch.push('network');
      return Promise.resolve({
        ok: true, status: 200,
        json: function(){ return Promise.resolve({ connector: { status: 'ok' }, connections: [] }); },
      });
    };
    await ctx.refreshNetworkConsole();
    await Promise.resolve(); await Promise.resolve();
    var nextTick = calls.fetch.length;

    return { duringFlight: duringFlight, afterDone: afterDone, nextTick: nextTick };
    """
    js_wrapped = "(async () => {\n" + js + "\n})().then(function(v){ console.log(JSON.stringify(v)); })"
    out = _run_harness(js_wrapped)

    assert out["duringFlight"] == 1  # второй тик пропущен — шторма нет
    assert out["afterDone"] == 1     # первый запрос завершился, новых нет
    assert out["nextTick"] == 2      # флаг сброшен — poll жив
