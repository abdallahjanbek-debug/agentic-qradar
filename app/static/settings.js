(function () {
  'use strict';

  // QRadar.fetch adds the QRadarCSRF header that use_qradar_csrf requires on PUT/POST/DELETE.
  var qradar = window.qappfw && window.qappfw.QRadar;
  var send = qradar ? qradar.fetch.bind(qradar) : window.fetch.bind(window);

  var cards = Array.prototype.slice.call(document.querySelectorAll('[data-setting]'));

  function call(method, url, body) {
    var init = { method: method, headers: {} };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return send(url, init).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (data) {
        if (!resp.ok) throw new Error(data.error || ('Request failed: HTTP ' + resp.status));
        return data;
      });
    });
  }

  function showStatus(card, info) {
    var status = card.querySelector('.status');
    var configured = info && info.configured;
    status.className = 'status ' + (configured ? 'ok' : 'missing');
    if (!configured) {
      status.textContent = 'Not configured.';
    } else {
      var when = info.updated ? ', saved ' + new Date(info.updated).toLocaleString() : '';
      status.textContent = 'Configured: ending in ••••' + (info.hint || '') + when + '.';
    }
    card.querySelector('[data-action="test"]').disabled = !configured;
    card.querySelector('[data-action="delete"]').disabled = !configured;
  }

  function showAll(summary) {
    cards.forEach(function (card) { showStatus(card, summary[card.dataset.setting]); });
  }

  function showResult(card, kind, text) {
    var result = card.querySelector('.result');
    result.className = 'result ' + kind;
    result.textContent = text;
  }

  function busy(card, isBusy) {
    Array.prototype.forEach.call(card.querySelectorAll('button, input'), function (el) {
      el.disabled = isBusy;
    });
  }

  function run(card, promise, pending) {
    showResult(card, 'pending', pending);
    busy(card, true);
    return promise
      .then(function (data) {
        showResult(card, data.verified === false ? 'warn' : 'ok', data.message);
        if (data.settings) showAll(data.settings);
      })
      .catch(function (err) { showResult(card, 'error', err.message); })
      .then(function () {
        busy(card, false);
        return call('GET', 'api/settings').then(function (data) { showAll(data.settings); });
      })
      .catch(function () { /* keep the last status shown */ });
  }

  cards.forEach(function (card) {
    var name = card.dataset.setting;
    var form = card.querySelector('form');
    var input = form.querySelector('input');

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      var value = input.value.trim();
      if (!value) {
        showResult(card, 'error', 'Paste a value first.');
        return;
      }
      input.value = '';
      run(card, call('PUT', 'api/settings/' + name, { value: value }), 'Checking and saving…');
    });

    card.querySelector('[data-action="test"]').addEventListener('click', function () {
      run(card, call('POST', 'api/settings/' + name + '/test'), 'Testing…');
    });

    card.querySelector('[data-action="delete"]').addEventListener('click', function () {
      var label = card.querySelector('h2').textContent;
      if (!window.confirm('Remove the saved ' + label + '? Features that use it stop working.')) {
        return;
      }
      run(card, call('DELETE', 'api/settings/' + name), 'Removing…');
    });
  });

  call('GET', 'api/settings')
    .then(function (data) { showAll(data.settings); })
    .catch(function (err) {
      cards.forEach(function (card) {
        card.querySelector('.status').textContent = '';
        showResult(card, 'error', err.message);
        busy(card, true);
      });
    });

  var theme = new URLSearchParams(window.location.search).get('theme');
  if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme;
})();
