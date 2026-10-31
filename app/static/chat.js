(function () {
  'use strict';

  // QRadar.fetch adds the QRadarCSRF header that use_qradar_csrf requires on POSTs.
  var qradar = window.qappfw && window.qappfw.QRadar;
  var send = qradar ? qradar.fetch.bind(qradar) : window.fetch.bind(window);

  var messages = document.getElementById('messages');
  var form = document.getElementById('ask-form');
  var input = document.getElementById('question');
  var button = document.getElementById('send');
  var upload = document.getElementById('upload');
  var uploadLabel = document.getElementById('upload-label');

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function addMessage(role, content) {
    var msg = el('div', 'message ' + role);
    var bubble = el('div', 'bubble');
    if (typeof content === 'string') bubble.appendChild(el('p', null, content));
    else bubble.appendChild(content);
    msg.appendChild(bubble);
    messages.appendChild(msg);
    messages.scrollTop = messages.scrollHeight;
    return bubble;
  }

  function formatTime(ms) {
    return ms ? new Date(ms).toLocaleString() : '—';
  }

  function setBusy(busy) {
    button.disabled = busy;
    upload.disabled = busy;
    uploadLabel.classList.toggle('disabled', busy);
  }

  // Feature-specific detail under the answer text. Each feature adds its own renderer here.
  function logSourceTable(matches) {
    var withTarget = matches.some(function (m) { return m.target; });
    var columns = ['Log source', 'Type', 'Identifier', 'State', 'Last event', 'Avg EPS',
      'Collector'];
    if (withTarget) columns.unshift('Target');
    var table = el('table', 'matches');
    var head = el('tr');
    columns.forEach(function (h) { head.appendChild(el('th', null, h)); });
    table.appendChild(el('thead')).appendChild(head);
    var body = table.appendChild(el('tbody'));

    matches.forEach(function (m) {
      var row = el('tr');
      if (withTarget) row.appendChild(el('td', 'mono', m.target));
      var name = el('td');
      name.appendChild(el('div', 'name', m.name));
      (m.messages || []).forEach(function (text) { name.appendChild(el('div', 'note', text)); });
      row.appendChild(name);
      row.appendChild(el('td', null, m.type));
      row.appendChild(el('td', 'mono', m.identifier));
      var state = el('td');
      state.appendChild(el('span', 'pill ' + m.state, m.state_label));
      row.appendChild(state);
      var last = el('td', null, formatTime(m.last_event_time));
      if (m.last_event_age) last.title = m.last_event_age + ' ago';
      row.appendChild(last);
      row.appendChild(el('td', 'num',
        m.average_eps === null || m.average_eps === undefined ? '—' : String(m.average_eps)));
      row.appendChild(el('td', null, m.collector));
      body.appendChild(row);
    });

    var wrap = el('div', 'table-wrap');
    wrap.appendChild(table);
    return wrap;
  }

  function downloadButton(base64, filename) {
    var bytes = Uint8Array.from(window.atob(base64), function (c) { return c.charCodeAt(0); });
    var blob = new Blob([bytes], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    });
    var url = URL.createObjectURL(blob);
    var link = el('a', 'download', 'Download ' + filename);
    link.href = url;
    link.download = filename;
    link.setAttribute('role', 'button');
    return link;
  }

  function bulkSummary(data) {
    var counts = el('div', 'counts');
    [['connected', data.counts.connected + ' connected'],
      ['silent', data.counts.not_connected + ' not connected'],
      ['disabled', data.counts.not_found + ' not found']].forEach(function (pair) {
      counts.appendChild(el('span', 'pill ' + pair[0], pair[1]));
    });
    return counts;
  }

  function renderAnswer(bubble, data) {
    bubble.textContent = '';
    bubble.appendChild(el('p', null, data.answer));
    if (data.feature === 'log_source_status' && data.matches && data.matches.length) {
      bubble.appendChild(logSourceTable(data.matches));
    }
    if (data.feature === 'bulk_check') {
      bubble.appendChild(bulkSummary(data));
      bubble.appendChild(downloadButton(data.file_base64, data.filename));
    }
  }

  function run(userText, pendingText, url, init) {
    addMessage('user', userText);
    var bubble = addMessage('assistant pending', pendingText);
    setBusy(true);

    send(url, init)
      .then(function (resp) {
        return resp.json().catch(function () { return {}; }).then(function (data) {
          if (!resp.ok) throw new Error(data.error || ('Request failed: HTTP ' + resp.status));
          return data;
        });
      })
      .then(function (data) {
        bubble.parentNode.classList.remove('pending');
        renderAnswer(bubble, data);
      })
      .catch(function (err) {
        bubble.parentNode.classList.remove('pending');
        bubble.parentNode.classList.add('error');
        bubble.textContent = '';
        bubble.appendChild(el('p', null, err.message));
      })
      .then(function () {
        setBusy(false);
        input.focus();
        messages.scrollTop = messages.scrollHeight;
      });
  }

  function ask(question) {
    run(question, 'Checking QRadar…', 'api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: question })
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var question = input.value.trim();
    if (!question || button.disabled) return;
    input.value = '';
    ask(question);
  });

  upload.addEventListener('change', function () {
    var file = upload.files[0];
    upload.value = '';
    if (!file) return;
    var body = new FormData();
    body.append('file', file);
    // No Content-Type header: the browser sets the multipart boundary itself.
    run('Uploaded ' + file.name, 'Checking every row against QRadar…', 'api/bulk_check',
      { method: 'POST', body: body });
  });

  messages.addEventListener('click', function (event) {
    if (event.target.classList.contains('suggestion') && !button.disabled) {
      ask(event.target.textContent);
    }
  });

  // QRadar 7.5.0 UP12+ passes ?theme=dark|light on first load; older consoles pass nothing.
  var theme = new URLSearchParams(window.location.search).get('theme');
  if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme;

  input.focus();
})();
