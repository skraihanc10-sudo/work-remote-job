/* Two small conveniences. Every page works without this file.

   The countdown is a display of a deadline the server already set and will
   enforce on its own - nothing here decides whether a submission is on time.
*/

(function () {
  'use strict';

  // ----------------------------------------------------- task countdown
  var timer = document.querySelector('.timer[data-deadline]');
  if (timer) {
    var deadline = Number(timer.dataset.deadline);
    var out = timer.querySelector('.t-left b');

    var tick = function () {
      var left = Math.max(0, deadline - Date.now());
      var m = Math.floor(left / 60000);
      var s = Math.floor((left % 60000) / 1000);
      out.textContent = m + ':' + String(s).padStart(2, '0');
      if (left <= 0) {
        timer.classList.add('over');
        timer.querySelector('.t-left').innerHTML =
          'Your time is up. <b>Submit now</b> - the slot may have been released.';
        clearInterval(handle);
      } else if (left < 5 * 60000) {
        timer.classList.add('over');
      }
    };
    tick();
    var handle = setInterval(tick, 1000);
  }

  // -------------------------------------------------- job cost preview
  // Posting a job spends real money, so show the total before the click,
  // not in an error afterwards.
  var costBox = document.getElementById('cost-preview');
  if (costBox) {
    var rate = document.getElementById('f-rate');
    var slots = document.getElementById('f-slots');
    var out2 = costBox.querySelector('b');

    var update = function () {
      var r = parseFloat(String(rate.value).replace(/,/g, ''));
      var n = parseInt(slots.value, 10);
      if (!isFinite(r) || !isFinite(n) || r <= 0 || n <= 0) {
        out2.textContent = '--';
        costBox.firstChild.textContent = 'Cost: ';
        return;
      }
      out2.textContent = (r * n).toFixed(2);
      costBox.firstChild.textContent = n + ' tasks x ' + r.toFixed(2) + ' = ';
    };
    rate.addEventListener('input', update);
    slots.addEventListener('input', update);
    update();
  }
})();

/* Support conversation: pull in new messages so a reply appears without a
   refresh. Polling, not a socket - a support queue this size does not need one,
   and the page still works if this never runs. */
(function () {
  'use strict';
  var body = document.getElementById('chat-body');
  if (!body) return;

  var ticket = body.dataset.ticket;
  var last = Number(body.dataset.last) || 0;
  body.scrollTop = body.scrollHeight;

  function add(m) {
    var wrap = document.createElement('div');
    wrap.className = 'msg ' + (m.from_staff ? 'staff' : 'mine');
    var who = document.createElement('div');
    who.className = 'who';
    who.textContent = m.from_staff ? 'Support' : 'You';
    var bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = m.body;
    wrap.appendChild(who);
    wrap.appendChild(bubble);
    body.appendChild(wrap);
  }

  setInterval(function () {
    if (document.hidden) return;
    fetch('/api/support/' + ticket + '/messages?after=' + last, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.messages || !d.messages.length) return;
        d.messages.forEach(function (m) { add(m); last = m.id; });
        body.scrollTop = body.scrollHeight;
      })
      .catch(function () { /* offline for a moment; the next tick retries */ });
  }, 6000);
})();

/* The deposit form: pick a way to pay, pick an amount, see what lands.

   The form posts to a different route depending on the method, so choosing one
   swaps the action. Everything here is a courtesy - the server recomputes the
   amount from the same setting and enforces the minimum itself, because a
   figure worked out in the browser is a suggestion, not a fact.
*/
(function () {
  'use strict';
  var form = document.getElementById('deposit-form');
  var input = document.getElementById('usd-input');
  var out = document.getElementById('amt-out');
  if (!form || !input || !out) return;

  var rate = Number(input.dataset.rate) || 0;
  var symbol = input.dataset.currency || '';
  var base = out.textContent;

  function money(units) {
    return symbol + (units / 100).toLocaleString('en-US',
      { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function chosen() {
    return form.querySelector('input[name="method"]:checked');
  }

  function show() {
    var usd = parseFloat(input.value);
    if (!isFinite(usd) || usd <= 0) { out.textContent = base; return; }

    var pick = chosen();
    var isEps = pick && pick.value === 'eps';
    // EPS is charged in whole units, so the figure is rounded up the same way
    // the server rounds it. Showing the unrounded number here and charging the
    // rounded one is exactly the surprise this line exists to prevent.
    var units = isEps ? Math.ceil((usd * rate) / 100) * 100 : Math.round(usd * rate);

    out.textContent = isEps
      ? 'You will pay ' + money(units) + ' and ' + money(units) + ' is added to your balance.'
      : 'About ' + money(units) + ' is added to your balance, at ' + money(rate) + ' to the dollar.';
  }

  input.addEventListener('input', show);

  // Choosing a method swaps where the form posts, and re-marks the card.
  form.addEventListener('change', function (e) {
    if (!e.target || e.target.name !== 'method') return;
    var action = e.target.dataset.action;
    if (action) form.setAttribute('action', action);
    var labels = form.querySelectorAll('.pay');
    for (var i = 0; i < labels.length; i++) {
      labels[i].classList.toggle('on', labels[i].contains(e.target));
    }
    show();
  });

  // The quick amounts are a shortcut for the field, not a separate thing.
  var quick = form.querySelectorAll('.amt');
  for (var i = 0; i < quick.length; i++) {
    quick[i].addEventListener('click', function () {
      input.value = this.dataset.usd;
      var all = form.querySelectorAll('.amt');
      for (var j = 0; j < all.length; j++) all[j].classList.remove('on');
      this.classList.add('on');
      show();
      input.focus();
    });
  }

  // Typing a number by hand should clear any highlighted shortcut.
  input.addEventListener('input', function () {
    var all = form.querySelectorAll('.amt');
    for (var j = 0; j < all.length; j++) {
      all[j].classList.toggle('on', all[j].dataset.usd === input.value);
    }
  });
})();

/* Copy the referral link. Falls back to selecting it, which is one keystroke
   away, because the clipboard API is blocked in more contexts than people
   expect. */
(function () {
  'use strict';
  var btn = document.getElementById('ref-copy');
  var input = document.getElementById('ref-link');
  if (!btn || !input) return;

  btn.addEventListener('click', function () {
    var done = function () {
      var was = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = was; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value).then(done).catch(function () {
        input.select(); btn.textContent = 'Press Ctrl+C';
      });
    } else {
      input.select();
      try { document.execCommand('copy'); done(); }
      catch (e) { btn.textContent = 'Press Ctrl+C'; }
    }
  });
})();

/* The phone menu. Kept in markup and toggled with the hidden attribute so the
   drawer's links are in the page for anyone whose JavaScript never runs - they
   simply see them in the normal flow instead of a panel. */
(function () {
  'use strict';
  var burger = document.getElementById('burger');
  var drawer = document.getElementById('drawer');
  var close = document.getElementById('drawer-close');
  if (!burger || !drawer) return;

  function open(yes) {
    drawer.hidden = !yes;
    burger.setAttribute('aria-expanded', String(yes));
    document.body.classList.toggle('drawer-open', yes);
  }

  burger.addEventListener('click', function () { open(drawer.hidden); });
  if (close) close.addEventListener('click', function () { open(false); });

  // Tapping the dimmed area behind the panel closes it, which is what everyone
  // tries first.
  drawer.addEventListener('click', function (e) {
    if (e.target === drawer) open(false);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !drawer.hidden) open(false);
  });
})();

/* The withdrawal form: a bank transfer needs two more fields than a wallet
   does. Hidden rather than absent so the values survive switching back and
   forth, and marked required only while they are actually showing - a
   required field the browser cannot see blocks the form with no visible
   explanation. */
(function () {
  'use strict';
  var form = document.getElementById('withdraw-form');
  if (!form) return;
  var method = document.getElementById('w-method');
  var bank = document.getElementById('bank-only');
  if (!method || !bank) return;

  function sync() {
    var isBank = method.value === 'bank';
    bank.hidden = !isBank;
    var fields = bank.querySelectorAll('input');
    for (var i = 0; i < fields.length; i++) fields[i].required = isBank;
  }
  method.addEventListener('change', sync);
  sync();
})();
