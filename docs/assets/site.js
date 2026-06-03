/* Keyroost Learn site — tiny, dependency-free progressive enhancement.
   1) marks the active nav link  2) wires the dark/light theme toggle.
   The no-flash theme decision happens inline in each page's <head>. */
(function () {
  // --- active nav link ---
  var here = (location.pathname.split('/').pop() || 'index.html');
  if (here === '') here = 'index.html';
  document.querySelectorAll('.kr-nav a').forEach(function (a) {
    if (a.getAttribute('href') === here) a.classList.add('active');
  });

  // --- theme toggle (dark is default; light is opt-in via data-theme) ---
  var btn = document.getElementById('kr-theme-toggle');
  function isLight() { return document.documentElement.getAttribute('data-theme') === 'light'; }
  function paint() { if (btn) btn.textContent = isLight() ? '◑' : '◐'; } // ◑ / ◐
  if (btn) {
    paint();
    btn.addEventListener('click', function () {
      if (isLight()) {
        document.documentElement.removeAttribute('data-theme');
        try { localStorage.setItem('kr-theme', 'dark'); } catch (e) {}
      } else {
        document.documentElement.setAttribute('data-theme', 'light');
        try { localStorage.setItem('kr-theme', 'light'); } catch (e) {}
      }
      paint();
    });
  }
})();
