(function () {
  'use strict';

  var shared = window.aiAdmin;
  var api = shared.api;
  var el = shared.el;
  var REFRESH_MS = 30000;

  var views = { chat: document.getElementById('view-chat'),
    findings: document.getElementById('view-findings') };
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.app-tab'));
  var list = document.getElementById('findings-list');
  var tasksBox = document.getElementById('findings-tasks');
  var severityFilter = document.getElementById('findings-severity');
  var statusFilter = document.getElementById('findings-status');
  var countLabel = document.getElementById('findings-count');
  var badge = document.getElementById('findings-badge');
  var timer = null;
  var expanded = {};  // finding id -> details open, kept across refreshes

  // ---- Views
  function showView(name) {
    Object.keys(views).forEach(function (key) { views[key].hidden = key !== name; });
    tabs.forEach(function (tab) { tab.classList.toggle('active', tab.dataset.view === name); });
    clearInterval(timer);
    if (name === 'findings') {
      load();
      timer = setInterval(load, REFRESH_MS);
    }
  }
  shared.showView = showView;
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () { showView(tab.dataset.view); });
  });

  // ---- Formatting
  function minutes(ms) {
    if (ms === null || ms === undefined) return '—';
    return ms >= 60000 ? (ms / 60000).toFixed(1) + ' min' : (ms / 1000).toFixed(1) + ' s';
  }
  function gigabytes(bytes) {
    if (!bytes) return '0 GB';
    return bytes >= 1e9 ? (bytes / 1e9).toFixed(1) + ' GB' : (bytes / 1e6).toFixed(1) + ' MB';
  }
  function when(ms) {
    return ms ? new Date(ms).toLocaleString() : '—';
  }
  function range(seconds) {
    if (!seconds) return '—';
    if (seconds >= 86400) return (seconds / 86400).toFixed(1) + ' days';
    if (seconds >= 3600) return (seconds / 3600).toFixed(1) + ' h';
    return Math.round(seconds / 60) + ' min';
  }

  // ---- Rendering
  function renderTasks(tasks) {
    tasksBox.textContent = '';
    tasks.forEach(function (task) {
      var box = el('div', 'findings-task');
      var run = task.last_run;
      var status = !task.enabled ? 'Off' :
        task.run_requested ? 'Run requested…' :
        !run ? 'Waiting for the first run' :
        run.status === 'running' ? 'Running…' :
        'Last run ' + when(run.finished || run.started) + ' · ' + run.status +
          (run.status === 'completed' ? ' · ' + run.new_findings + ' new, ' + run.updated_findings +
            ' updated' : '');
      box.appendChild(el('div', 'findings-task-name', task.name + ' · every ' +
        task.interval_minutes + ' min'));
      box.appendChild(el('div', 'findings-task-status', status));
      if (run && run.status === 'failed' && run.message) {
        box.appendChild(el('div', 'findings-task-error', run.message));
      }
      var button = el('button', 'secondary', 'Run now');
      button.type = 'button';
      button.disabled = !task.enabled || task.run_requested;
      button.addEventListener('click', function () {
        button.disabled = true;
        api('POST', 'api/findings/tasks/' + task.task + '/run').then(load)
          .catch(function (err) { window.alert(err.message); button.disabled = false; });
      });
      box.appendChild(button);
      tasksBox.appendChild(box);
    });
  }

  function stat(table, label, value) {
    var row = el('tr');
    row.appendChild(el('th', null, label));
    row.appendChild(el('td', null, value));
    table.appendChild(row);
  }

  function action(card, label, onClick, className) {
    var button = el('button', className || 'secondary', label);
    button.type = 'button';
    button.addEventListener('click', onClick);
    card.actions.appendChild(button);
  }

  function setStatus(finding, status) {
    api('PUT', 'api/findings/' + finding.id + '/status', { status: status }).then(load)
      .catch(function (err) { window.alert(err.message); });
  }

  function renderFinding(finding) {
    var d = finding.details || {};
    var card = el('article', 'finding ' + finding.severity);
    var head = el('div', 'finding-head');
    head.appendChild(el('span', 'pill sev-' + finding.severity, finding.severity));
    head.appendChild(el('h2', null, finding.title));
    if (finding.status !== 'open') head.appendChild(el('span', 'pill status', finding.status));
    card.appendChild(head);

    card.appendChild(el('p', 'finding-meta', [
      (d.user || 'unknown') + ' · ' + (d.source || 'unknown'),
      finding.occurrences + ' time' + (finding.occurrences === 1 ? '' : 's'),
      'first ' + when(finding.first_seen), 'last ' + when(finding.last_seen)
    ].join(' · ')));

    var reasons = el('ul', 'finding-reasons');
    (d.reasons || []).forEach(function (r) { reasons.appendChild(el('li', null, r)); });
    card.appendChild(reasons);

    var details = el('details', 'finding-details');
    details.open = !!expanded[finding.id];
    details.addEventListener('toggle', function () { expanded[finding.id] = details.open; });
    details.appendChild(el('summary', null, 'Details, query and analysis'));

    var last = d.last || {};
    var worst = d.worst || {};
    var table = el('table', 'finding-stats');
    stat(table, 'Search time (latest / worst)', minutes(last.search_ms) + ' / ' + minutes(worst.search_ms));
    stat(table, 'Data scanned (latest / worst)', gigabytes(last.data_bytes) + ' / ' + gigabytes(worst.data_bytes));
    stat(table, 'Files scanned', (last.data_files || 0) + ' data, ' + (last.index_files || 0) + ' index');
    stat(table, 'Results', last.results === undefined ? '—' : String(last.results));
    stat(table, 'Concurrent searches', last.concurrent === undefined || last.concurrent === null ? '—' : String(last.concurrent));
    stat(table, 'Time range searched', range(d.window_seconds) +
      (d.window_from ? ' (' + d.window_from + ' to ' + d.window_to + ')' : ''));
    stat(table, 'Database / status', (d.db || '—') + ' / ' + (last.status || 'running'));
    details.appendChild(table);

    details.appendChild(el('div', 'finding-label', d.aql ? 'AQL' :
      d.filters ? 'Log Activity filters' : 'Filter criteria (as QRadar parsed them)'));
    details.appendChild(el('pre', 'aql', d.aql || d.filters || d.criteria || 'Not recorded'));
    if (d.aql) details.appendChild(shared.logActivityLink(d.aql));

    details.appendChild(el('div', 'finding-label', 'Analysis'));
    var analysis = el('div', 'answer finding-analysis');
    if (finding.analysis) {
      analysis.innerHTML = shared.markdown(finding.analysis);
      if (finding.analysis_model) analysis.appendChild(el('div', 'answered-by', finding.analysis_model));
    } else {
      analysis.appendChild(el('p', 'muted', finding.needs_analysis ? 'Analysis pending…' : 'Not analysed yet.'));
    }
    details.appendChild(analysis);
    card.appendChild(details);

    card.actions = el('div', 'finding-actions');
    if (finding.status === 'open') {
      action(card, 'Acknowledge', function () { setStatus(finding, 'acknowledged'); });
    }
    if (finding.status !== 'resolved') {
      action(card, 'Resolve', function () { setStatus(finding, 'resolved'); });
    }
    if (finding.status !== 'ignored') {
      action(card, 'Ignore this query', function () {
        if (window.confirm('Ignore this query from now on? It keeps being counted but stays out of the open list.')) {
          setStatus(finding, 'ignored');
        }
      });
    }
    if (finding.status !== 'open') action(card, 'Reopen', function () { setStatus(finding, 'open'); });
    action(card, finding.analysis ? 'Re-analyse' : 'Analyse', function () {
      api('POST', 'api/findings/' + finding.id + '/analyse').then(load)
        .catch(function (err) { window.alert(err.message); });
    });
    action(card, 'Ask the agent about this', function () {
      api('POST', 'api/findings/' + finding.id + '/chat').then(function (data) {
        shared.openChatWith(data.chat_id, 'Explain this finding and how to fix it.');
      }).catch(function (err) { window.alert(err.message); });
    }, 'primary');
    card.appendChild(card.actions);
    return card;
  }

  function render(data) {
    renderTasks(data.tasks);
    list.textContent = '';
    countLabel.textContent = data.findings.length + ' finding' + (data.findings.length === 1 ? '' : 's');
    if (!data.findings.length) {
      var running = data.tasks.some(function (t) { return t.enabled; });
      list.appendChild(el('p', 'findings-empty', running ?
        'No findings match. AI Admin keeps checking on schedule; expensive searches appear here as they happen.' :
        'All findings tasks are off. Turn them on in Admin > AI Admin Settings.'));
      return;
    }
    data.findings.forEach(function (f) { list.appendChild(renderFinding(f)); });
  }

  function query() {
    var params = [];
    if (severityFilter.value) params.push('severity=' + encodeURIComponent(severityFilter.value));
    if (statusFilter.value) params.push('status=' + encodeURIComponent(statusFilter.value));
    return 'api/findings' + (params.length ? '?' + params.join('&') : '');
  }

  function load() {
    return api('GET', query()).then(render).then(updateBadge)
      .catch(function (err) {
        list.textContent = '';
        list.appendChild(el('p', 'findings-empty error-text', err.message));
      });
  }

  // Open critical and warning findings, shown on the Findings tab.
  function updateBadge() {
    return api('GET', 'api/findings?status=open').then(function (data) {
      var count = data.findings.filter(function (f) { return f.severity !== 'info'; }).length;
      badge.textContent = String(count);
      badge.hidden = count === 0;
      badge.classList.toggle('critical', data.findings.some(function (f) { return f.severity === 'critical'; }));
    }).catch(function () {});
  }

  severityFilter.addEventListener('change', load);
  statusFilter.addEventListener('change', load);
  updateBadge();
  setInterval(updateBadge, 5 * 60000);
})();
