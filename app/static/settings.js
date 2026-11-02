(function () {
  'use strict';

  // QRadar.fetch adds the QRadarCSRF header that use_qradar_csrf requires on PUT/POST/DELETE.
  var qradar = window.qappfw && window.qappfw.QRadar;
  var send = qradar ? qradar.fetch.bind(qradar) : window.fetch.bind(window);

  var cards = Array.prototype.slice.call(document.querySelectorAll('[data-setting]'));

  function call(method, url, body) {
    // Saving checks the credential against QRadar or Anthropic, which can exceed QRadar.fetch's
    // default 10 s timeout.
    var init = { method: method, headers: {}, timeout: 60000 };
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

  var limits = document.getElementById('search-limits');
  var windowInput = document.getElementById('window-days');

  function showConfig(config) {
    var spec = config && config.aql_max_window_days;
    if (!spec) return;
    windowInput.value = spec.value;
    windowInput.min = spec.min;
    windowInput.max = spec.max;
  }

  document.getElementById('window-form').addEventListener('submit', function (event) {
    event.preventDefault();
    var value = parseInt(windowInput.value, 10);
    showResult(limits, 'pending', 'Saving…');
    call('PUT', 'api/config/aql_max_window_days', { value: value })
      .then(function (data) {
        showConfig(data.config);
        showResult(limits, 'ok', 'Saved. Searches may now cover up to ' + value + ' days.');
      })
      .catch(function (err) { showResult(limits, 'error', err.message); });
  });

  var modelCard = document.getElementById('model-card');
  var modelSelect = document.getElementById('model-select');

  function loadModels() {
    return call('GET', 'api/models').then(function (data) {
      modelSelect.textContent = '';
      data.models.forEach(function (m) {
        var option = document.createElement('option');
        option.value = m.id;
        option.textContent = m.name + ' ($' + m.price_in + ' / $' + m.price_out + ') - ' + m.note +
          (m.fallback ? '' : ' No refusal fallback.') +
          (m.available === false ? ' [not available to this key]' : '');
        option.disabled = m.available === false;
        option.selected = m.id === data.current;
        modelSelect.appendChild(option);
      });
      if (data.note) showResult(modelCard, 'warn', data.note);
    }).catch(function (err) { showResult(modelCard, 'error', err.message); });
  }

  document.getElementById('model-form').addEventListener('submit', function (event) {
    event.preventDefault();
    showResult(modelCard, 'pending', 'Checking and saving…');
    call('PUT', 'api/config/claude_model', { value: modelSelect.value })
      .then(function (data) { showResult(modelCard, 'ok', data.message); })
      .catch(function (err) { showResult(modelCard, 'error', err.message); })
      .then(loadModels);
  });

  loadModels();

  call('GET', 'api/settings')
    .then(function (data) { showAll(data.settings); showConfig(data.config); })
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
