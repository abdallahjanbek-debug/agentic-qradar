(function () {
  'use strict';

  // QRadar.fetch adds the QRadarCSRF header that use_qradar_csrf requires on POSTs. It also
  // forces Content-Type: application/json and a 10 s timeout unless told otherwise.
  var qradar = window.qappfw && window.qappfw.QRadar;
  var send = qradar ? qradar.fetch.bind(qradar) : window.fetch.bind(window);
  var REQUEST_TIMEOUT_MS = 60000;
  var UPLOAD_TIMEOUT_MS = 180000;
  var POLL_MS = 700;

  var messages = document.getElementById('messages');
  var form = document.getElementById('ask-form');
  var input = document.getElementById('question');
  var sendButton = document.getElementById('send');
  var stopButton = document.getElementById('stop');
  var upload = document.getElementById('upload');
  var uploadLabel = document.getElementById('upload-label');
  var chatList = document.getElementById('chat-list');
  var chatTitle = document.getElementById('chat-title');
  var statusLine = document.getElementById('status');

  var state = { chatId: null, runId: null, busy: false };

  // ---- Markdown: Claude's answers are rendered, then sanitized. Images are forbidden so an
  // answer can never make the browser fetch a URL (which could leak data).
  DOMPurify.addHook('afterSanitizeAttributes', function (node) {
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });

  function markdown(text) {
    var html = marked.parse(text || '', { gfm: true, breaks: false, async: false });
    return DOMPurify.sanitize(html, {
      FORBID_TAGS: ['img', 'picture', 'video', 'audio', 'source', 'iframe', 'form', 'input',
        'button', 'style', 'svg', 'math'],
      FORBID_ATTR: ['style', 'srcset']
    });
  }

  // ---- HTTP helpers
  function readJson(resp) {
    return resp.json().catch(function () { return {}; }).then(function (data) {
      if (!resp.ok) throw new Error(data.error || ('Request failed: HTTP ' + resp.status));
      return data;
    });
  }

  function api(method, url, body) {
    var init = { method: method, headers: {}, timeout: REQUEST_TIMEOUT_MS };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return send(url, init).then(readJson);
  }

  // File uploads can't use QRadar.fetch: its JSON Content-Type replaces the multipart header
  // (and boundary) the browser must set, so the server sees no file. Send the CSRF header
  // ourselves instead.
  function sendForm(url, body) {
    var headers = {};
    var csrf = qradar && qradar.getCookie('QRadarCSRF');
    if (csrf) headers.QRadarCSRF = csrf;
    var timeout = new Promise(function (resolve, reject) {
      setTimeout(function () {
        reject(new Error('The upload took longer than ' + UPLOAD_TIMEOUT_MS / 1000 + ' s.'));
      }, UPLOAD_TIMEOUT_MS);
    });
    return Promise.race([
      window.fetch(url, { method: 'POST', body: body, headers: headers, credentials: 'same-origin' }),
      timeout
    ]).then(readJson);
  }

  // ---- DOM helpers
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function scrollDown() {
    messages.scrollTop = messages.scrollHeight;
  }

  function setBusy(busy) {
    state.busy = busy;
    sendButton.hidden = busy;
    stopButton.hidden = !busy;
    upload.disabled = busy;
    uploadLabel.classList.toggle('disabled', busy);
    if (!busy) statusLine.hidden = true;
  }

  function setStatus(text) {
    statusLine.textContent = text + '…';
    statusLine.hidden = false;
  }

  function userBubble(text, attachment) {
    var msg = el('div', 'message user');
    var bubble = el('div', 'bubble');
    if (attachment) bubble.appendChild(el('div', 'attachment', attachment.replace(/^\[|\]$/g, '')));
    bubble.appendChild(el('p', 'plain', text));
    msg.appendChild(bubble);
    messages.appendChild(msg);
    scrollDown();
  }

  // An assistant turn: tool activity, an optional reasoning summary and the answer text.
  function assistantBubble() {
    var msg = el('div', 'message assistant');
    var bubble = el('div', 'bubble');
    var tools = el('ul', 'tools');
    var reasoning = el('details', 'reasoning');
    reasoning.appendChild(el('summary', null, 'Reasoning'));
    var reasoningText = el('div', 'reasoning-text');
    reasoning.appendChild(reasoningText);
    reasoning.hidden = true;
    var answer = el('div', 'answer');
    bubble.appendChild(tools);
    bubble.appendChild(reasoning);
    bubble.appendChild(answer);
    msg.appendChild(bubble);
    messages.appendChild(msg);
    scrollDown();
    return { msg: msg, tools: tools, reasoning: reasoning, reasoningText: reasoningText,
      answer: answer, text: '', thinking: '' };
  }

  // An event search: the AQL that ran and its results, collapsed by default.
  function searchBlock(search) {
    var box = el('details', 'search');
    if (search.error) {
      box.appendChild(el('summary', 'search-failed', 'Event search failed'));
      box.appendChild(el('p', null, search.error));
      return box;
    }
    var count = search.rows.length;
    box.appendChild(el('summary', null, 'Event search: ' + count + ' event' +
      (count === 1 ? '' : 's') + (count >= search.limited_to ? ' (capped at ' +
      search.limited_to + ')' : '')));
    box.appendChild(el('pre', 'aql', search.aql));
    if (!count) return box;
    var table = el('table', 'matches');
    var head = el('tr');
    search.columns.forEach(function (c) { head.appendChild(el('th', null, c)); });
    table.appendChild(el('thead')).appendChild(head);
    var body = table.appendChild(el('tbody'));
    search.rows.forEach(function (row) {
      var tr = el('tr');
      search.columns.forEach(function (c) {
        var value = row[c] === null || row[c] === undefined ? '' : String(row[c]);
        var td = el('td', c === 'Payload' ? 'payload' : null,
          value.length > 160 ? value.slice(0, 160) + '…' : value);
        if (value.length > 160) td.title = value;
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    var wrap = el('div', 'table-wrap');
    wrap.appendChild(table);
    box.appendChild(wrap);
    return box;
  }

  function addTool(turn, label, done) {
    var item = el('li', done ? 'tool done' : 'tool running', label);
    turn.tools.appendChild(item);
    return item;
  }

  // kind: 'error' (red) or 'notice' (muted), e.g. a saved "Stopped by the user."
  function errorBubble(text, kind) {
    var msg = el('div', 'message assistant ' + (kind || 'error'));
    var bubble = el('div', 'bubble');
    bubble.appendChild(el('p', null, text));
    msg.appendChild(bubble);
    messages.appendChild(msg);
    scrollDown();
  }

  function uploadCard(chatId, item) {
    userBubble('Uploaded ' + item.filename, null);
    var turn = assistantBubble();
    turn.answer.appendChild(el('p', null, item.summary));
    var counts = el('div', 'counts');
    [['connected', item.counts.connected + ' connected'],
      ['silent', item.counts.not_connected + ' not connected'],
      ['disabled', item.counts.not_found + ' not found']].forEach(function (pair) {
      counts.appendChild(el('span', 'pill ' + pair[0], pair[1]));
    });
    turn.answer.appendChild(counts);
    var link = el('a', 'download', 'Download ' + item.result_filename);
    link.href = 'api/chats/' + chatId + '/uploads/' + item.id + '/result';
    link.setAttribute('download', item.result_filename);
    turn.answer.appendChild(link);
  }

  // The one place a chat is drawn: live answers are re-drawn from here when they finish, so
  // what you see live is exactly what a reload shows.
  function renderItems(chatId, items) {
    messages.textContent = '';
    if (!items.length) showWelcome();
    items.forEach(function (item) {
      if (item.role === 'user') {
        userBubble(item.text, item.attachment);
      } else if (item.role === 'upload') {
        uploadCard(chatId, item);
      } else if (item.kind) {
        errorBubble(item.text, item.kind);
      } else {
        var turn = assistantBubble();
        item.tools.forEach(function (label) { addTool(turn, label, true); });
        (item.searches || []).forEach(function (search) {
          turn.tools.parentNode.insertBefore(searchBlock(search), turn.answer);
        });
        turn.answer.innerHTML = markdown(item.text);
      }
    });
    scrollDown();
  }

  function showWelcome() {
    messages.textContent = '';
    messages.appendChild(document.getElementById('welcome-template').content.cloneNode(true));
  }

  // ---- Chats
  function renderChatList(chats) {
    chatList.textContent = '';
    chats.forEach(function (chat) {
      var item = el('li', chat.id === state.chatId ? 'chat-item active' : 'chat-item');
      var open = el('button', 'chat-open', chat.title);
      open.type = 'button';
      open.title = chat.title;
      open.addEventListener('click', function () { if (!state.busy) openChat(chat.id); });
      var remove = el('button', 'chat-delete', '×');
      remove.type = 'button';
      remove.title = 'Delete this chat';
      remove.setAttribute('aria-label', 'Delete chat ' + chat.title);
      remove.addEventListener('click', function () { deleteChat(chat); });
      item.appendChild(open);
      item.appendChild(remove);
      chatList.appendChild(item);
    });
  }

  function refreshChats() {
    return api('GET', 'api/chats').then(function (data) { renderChatList(data.chats); });
  }

  function newChat() {
    state.chatId = null;
    chatTitle.textContent = 'AI Admin';
    showWelcome();
    refreshChats();
    input.focus();
  }

  function ensureChat() {
    if (state.chatId) return Promise.resolve(state.chatId);
    return api('POST', 'api/chats').then(function (data) {
      state.chatId = data.chat.id;
      messages.textContent = '';
      return state.chatId;
    });
  }

  function openChat(chatId) {
    return api('GET', 'api/chats/' + chatId).then(function (data) {
      state.chatId = chatId;
      chatTitle.textContent = data.chat.title;
      renderItems(chatId, data.items);
      refreshChats();
      if (data.active_run && !state.busy) follow(data.active_run, assistantBubble());
      return data;
    }).catch(function (err) { errorBubble(err.message); });
  }

  function deleteChat(chat) {
    if (!window.confirm('Delete the chat "' + chat.title + '"? This cannot be undone.')) return;
    api('DELETE', 'api/chats/' + chat.id).then(function () {
      if (chat.id === state.chatId) newChat(); else refreshChats();
    }).catch(function (err) { window.alert(err.message); });
  }

  // ---- Runs: poll for events until the run is done.
  function follow(runId, turn) {
    state.runId = runId;
    setBusy(true);
    setStatus('Working');
    var next = 0;
    var running = {};
    var renderPending = false;

    function render() {
      renderPending = false;
      turn.answer.innerHTML = markdown(turn.text);
      scrollDown();
    }

    function apply(event) {
      if (event.type === 'status') {
        setStatus(event.text);
      } else if (event.type === 'text') {
        turn.text += event.text;
        if (!renderPending) { renderPending = true; setTimeout(render, 150); }
      } else if (event.type === 'thinking') {
        turn.thinking += event.text;
        turn.reasoning.hidden = false;
        turn.reasoningText.textContent = turn.thinking;
      } else if (event.type === 'reset_text') {
        turn.text = '';
        render();
      } else if (event.type === 'tool') {
        running[event.name] = addTool(turn, event.label, false);
        setStatus(event.label);
      } else if (event.type === 'tool_done') {
        var item = running[event.name];
        if (item) item.className = event.ok ? 'tool done' : 'tool failed';
      } else if (event.type === 'error') {
        errorBubble(event.message);
      }
    }

    function poll() {
      api('GET', 'api/runs/' + runId + '?after=' + next).then(function (data) {
        data.events.forEach(apply);
        next = data.next;
        if (data.done) {
          state.runId = null;
          setBusy(false);
          openChat(state.chatId).then(function () { input.focus(); });
        } else {
          setTimeout(poll, POLL_MS);
        }
      }).catch(function (err) {
        errorBubble(err.message);
        state.runId = null;
        setBusy(false);
      });
    }
    poll();
  }

  function ask(text) {
    if (state.busy) return;
    setBusy(true);
    ensureChat().then(function (chatId) {
      var welcome = messages.querySelector('.welcome');
      if (welcome) welcome.remove();
      userBubble(text, null);
      return api('POST', 'api/chats/' + chatId + '/messages', { text: text });
    }).then(function (data) {
      if (chatTitle.textContent === 'AI Admin') chatTitle.textContent = text.slice(0, 80);
      follow(data.run_id, assistantBubble());
    }).catch(function (err) {
      errorBubble(err.message);
      setBusy(false);
    });
  }

  // ---- Bulk upload
  function uploadFile(file) {
    setBusy(true);
    setStatus('Checking every row against QRadar');
    ensureChat().then(function (chatId) {
      var welcome = messages.querySelector('.welcome');
      if (welcome) welcome.remove();
      userBubble('Uploaded ' + file.name, null);
      var body = new FormData();
      body.append('file', file);
      return sendForm('api/chats/' + chatId + '/bulk_check', body);
    }).then(function () {
      setBusy(false);
      return openChat(state.chatId);
    }).then(function () {
      input.value = 'Review these bulk check results and tell me what to fix first.';
      input.focus();
    }).catch(function (err) {
      errorBubble(err.message);
      setBusy(false);
    });
  }

  // ---- Events
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var text = input.value.trim();
    if (!text || state.busy) return;
    input.value = '';
    ask(text);
  });

  input.addEventListener('keydown', function (event) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  stopButton.addEventListener('click', function () {
    if (!state.runId) return;
    setStatus('Stopping');
    api('POST', 'api/runs/' + state.runId + '/cancel').catch(function () {});
  });

  upload.addEventListener('change', function () {
    var file = upload.files[0];
    upload.value = '';
    if (file && !state.busy) uploadFile(file);
  });

  messages.addEventListener('click', function (event) {
    if (event.target.classList.contains('suggestion')) ask(event.target.textContent);
  });

  document.getElementById('new-chat').addEventListener('click', function () {
    if (!state.busy) newChat();
  });

  // QRadar 7.5.0 UP12+ passes ?theme=dark|light on first load; older consoles pass nothing.
  var theme = new URLSearchParams(window.location.search).get('theme');
  if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme;

  // Open the most recent chat, or show the welcome message.
  api('GET', 'api/chats').then(function (data) {
    renderChatList(data.chats);
    if (data.chats.length) openChat(data.chats[0].id); else showWelcome();
  }).catch(function (err) {
    showWelcome();
    errorBubble(err.message);
  });
  input.focus();
})();
