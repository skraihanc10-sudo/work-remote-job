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
