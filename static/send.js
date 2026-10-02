'use strict';
/* Sender-side additions to the walkthrough: the role switch and the "send to
   the receiver" step. They live here so walkthrough.js stays as it was. */
(function () {
  const byId = id => document.getElementById(id);

  if (new URLSearchParams(location.search).get('role') === 'sender') {
    document.body.classList.add('role-sender');
  }

  // The file on disk is named after the run; the receiver should see a name
  // that says what it is.
  function stegoFileName() {
    const href = byId('download').getAttribute('href') || '';
    const suffix = (href.match(/\.[A-Za-z0-9]+$/) || ['.png'])[0];
    const cover = (byId('sum-cover').textContent || 'cover').replace(/\.[^.]+$/, '');
    return 'stego_' + cover.replace(/[^\w.-]+/g, '_') + suffix;
  }

  function labelDownload() {
    const name = stegoFileName();
    const link = byId('download');
    link.textContent = 'Download ' + name;
    link.setAttribute('download', name);
  }

  // The passphrase stays out of the draft on purpose: it has to reach the
  // receiver by a different route, or the email would carry both halves.
  function draft() {
    const name = stegoFileName();
    return {
      subject: 'Protected file to verify: ' + name,
      body: [
        'Hello,',
        '',
        'I have attached ' + name + ', a protected file for you to verify.',
        '',
        'To check it, open the STEG app, choose "I am the Receiver", and upload the attached file together with the sender\'s public key (.pem).',
        '',
        'The passphrase is deliberately not in this email. I will send it to you separately.',
        '',
        'Thanks',
      ].join('\n'),
    };
  }

  function mailUrl(provider) {
    const { subject, body } = draft();
    const enc = encodeURIComponent;
    const compose = provider === 'gmail'
      ? 'https://mail.google.com/mail/?view=cm&fs=1&su='
      : 'https://outlook.office.com/mail/deeplink/compose?subject=';
    return compose + enc(subject) + '&body=' + enc(body);
  }

  byId('to-transfer').addEventListener('click', labelDownload);
  document.querySelector('.progress').addEventListener('click', labelDownload);

  document.querySelector('.send-mail').addEventListener('click', event => {
    const button = event.target.closest('[data-mail]');
    if (!button) return;
    labelDownload();
    window.open(mailUrl(button.dataset.mail), '_blank', 'noopener');
  });
})();
