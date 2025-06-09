const statusEl = document.getElementById('status');
  const logEl = document.getElementById('log');
  const inputEl = document.getElementById('messageInput');
  const sendBtn = document.getElementById('sendBtn');

  let socket;

  function setStatus(connected = false, error = false, reason = '') {
    if (error) {
      statusEl.textContent = `Error: ${reason}`;
      statusEl.style.color = '#d9534f';
      inputEl.disabled = true;
      sendBtn.disabled = true;
    } else if (connected) {
      statusEl.textContent = 'Connected';
      statusEl.style.color = '#28a745';
      inputEl.disabled = false;
      sendBtn.disabled = false;
      inputEl.focus();
    } else {
      statusEl.textContent = 'Connecting...';
      statusEl.style.color = '#555';
      inputEl.disabled = true;
      sendBtn.disabled = true;
    }
  }

  function log(message, type = 'system') {
    const p = document.createElement('p');
    p.textContent = message;
    p.classList.add(type);
    logEl.appendChild(p);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function initWebSocket() {
    setStatus(false);
    socket = new WebSocket('ws://localhost:9002/');

    socket.addEventListener('open', () => {
      setStatus(true);
      log('Connection opened', 'system');
    });

    socket.addEventListener('message', (event) => {
      log('⬅️ Received: ' + event.data, 'received');
    });

    socket.addEventListener('error', (event) => {
      setStatus(false, true, event.message || 'WebSocket error');
      log('Error occurred', 'system');
    });

    socket.addEventListener('close', (event) => {
      setStatus(false);
      log(`Connection closed (code: ${event.code})`, 'system');
      // Optional: auto reconnect after 3 seconds
      setTimeout(() => {
        log('Reconnecting...');
        initWebSocket();
      }, 3000);
    });
  }

  sendBtn.addEventListener('click', () => {
    const message = inputEl.value.trim();
    if (message && socket.readyState === WebSocket.OPEN) {
      socket.send(message);
      log('➡️ Sent: ' + message, 'sent');
      inputEl.value = '';
      inputEl.focus();
    }
  });

  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendBtn.click();
  });

  initWebSocket();