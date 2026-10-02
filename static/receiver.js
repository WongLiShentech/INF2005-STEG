'use strict';
/* Receiver page: upload the received file and the sender's public key, send
   them to /api/receive, and show the verdict with the checks behind it. */
(function () {
  const byId = id => document.getElementById(id);

  function renderVerdict(d) {
    const box = byId('verdict');
    const title = document.createElement('h3');
    const text = document.createElement('p');
    title.textContent = d.verdict;
    text.textContent = d.explanation;
    box.replaceChildren(title, text);
    box.className = 'verdict' + (d.verdict === 'Authentic' ? '' : ' bad');
  }

  function renderTrail(checks) {
    const list = byId('trail');
    list.replaceChildren();
    for (const check of checks) {
      const item = document.createElement('li');
      const mark = document.createElement('b');
      const body = document.createElement('div');
      const title = document.createElement('strong');
      const detail = document.createElement('small');
      mark.textContent = check.ok ? 'PASS' : 'FAIL';
      if (!check.ok) mark.style.color = '#a03b24';
      title.textContent = check.label;
      detail.textContent = check.detail;
      body.append(title, detail);
      if (check.compared && check.compared.length) {
        const more = document.createElement('details');
        const summary = document.createElement('summary');
        const values = document.createElement('pre');
        more.open = !check.ok;
        summary.textContent = 'Compare SHA-256 values';
        values.className = 'hash';
        values.textContent = check.compared.map(([name, value]) => name + ': ' + value).join('\n');
        more.append(summary, values);
        body.append(more);
      }
      item.append(mark, body);
      list.append(item);
    }
  }

  function renderPayload(d) {
    const box = byId('payload');
    box.replaceChildren();
    byId('recovered').hidden = !d.payload_url;
    if (!d.payload_url) return;

    const type = d.payload_type || '';
    if (type === 'text/plain') {
      box.textContent = d.message_text;
      return;
    }
    const tag = type.startsWith('image/') ? 'img'
      : type.startsWith('audio/') ? 'audio'
      : type.startsWith('video/') ? 'video' : null;
    if (tag) {
      const media = document.createElement(tag);
      media.src = d.payload_url;
      if (tag === 'img') media.alt = 'Recovered payload';
      else media.controls = true;
      box.append(media);
      return;
    }
    const link = document.createElement('a');
    link.href = d.payload_url;
    link.textContent = 'Download recovered payload';
    box.append(link);
  }

  function renderRecord(d) {
    byId('record-box').hidden = !d.record;
    if (d.record) {
      byId('record').textContent = 'Public key ' + d.key + ', SHA-256 ' + d.public_fingerprint
        + '\n\n' + JSON.stringify(d.record, null, 2);
    }
  }

  byId('receive-form').addEventListener('submit', async event => {
    event.preventDefault();
    const button = byId('verify');
    byId('receive-error').textContent = '';
    button.disabled = true;
    button.textContent = 'Verifying...';
    try {
      const response = await fetch('/api/receive', { method: 'POST', body: new FormData(event.target) });
      let d;
      try {
        d = await response.json();
      } catch {
        throw Error('Unexpected server response. Reload the page and try again.');
      }
      if (!response.ok || d.error) throw Error(d.error || 'Verification failed.');

      renderVerdict(d);
      renderTrail(d.checks);
      renderPayload(d);
      renderRecord(d);
      byId('result').hidden = false;
      byId('check').hidden = true;
      byId('result').scrollIntoView({ block: 'start' });
    } catch (error) {
      byId('receive-error').textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Verify';
    }
  });

  byId('again').addEventListener('click', () => {
    byId('receive-form').reset();
    byId('result').hidden = true;
    byId('check').hidden = false;
    byId('stego-file').focus();
  });
})();
