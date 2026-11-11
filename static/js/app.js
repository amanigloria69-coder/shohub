// Client-side helpers. The server always re-validates everything.
(function () {
  const EYE = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

  // Show / hide password (eye icon) on every password field
  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    const wrap = document.createElement('div');
    wrap.className = 'pw-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-toggle';
    btn.setAttribute('aria-label', 'Show password');
    btn.innerHTML = EYE_OFF;
    btn.addEventListener('click', function () {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.innerHTML = show ? EYE : EYE_OFF;
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
    wrap.appendChild(btn);
  });

  // Password strength meter
  const pw = document.getElementById('password');
  const meter = document.getElementById('strength');
  if (pw && meter) {
    pw.addEventListener('input', function () {
      const v = pw.value;
      let score = 0;
      if (v.length >= 8) score++;
      if (/[A-Za-z]/.test(v) && /\d/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 12) score++;
      const labels = ['Too weak', 'Weak', 'Good', 'Strong'];
      meter.textContent = v ? 'Strength: ' + labels[score] : '';
      meter.className = 'strength-' + score;
    });
  }

  // Confirm-password check
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (ev) {
      if (form.password.value !== form.confirm_password.value) {
        ev.preventDefault();
        alert('Passwords do not match.');
      }
    });
  });

  // On the register page, social sign-up uses the chosen role (Buyer / Seller)
  const role = document.getElementById('roleSelect');
  if (role) {
    const update = function () {
      document.querySelectorAll('a[data-social]').forEach(function (a) {
        const base = a.getAttribute('href').split('?')[0];
        a.setAttribute('href', base + '?role=' + encodeURIComponent(role.value));
      });
    };
    role.addEventListener('change', update);
    update();
  }

  // Slide-out navigation menu.
  const menuToggle = document.querySelector('.menu-toggle');
  const sideMenu = document.querySelector('.side-menu');
  const menuOverlay = document.querySelector('[data-menu-overlay]');
  const menuClose = document.querySelector('[data-menu-close]');

  const setMenuOpen = function (open) {
    if (!sideMenu || !menuOverlay || !menuToggle) return;
    sideMenu.classList.toggle('is-open', open);
    menuOverlay.classList.toggle('is-open', open);
    document.body.classList.toggle('menu-open', open);
    sideMenu.setAttribute('aria-hidden', open ? 'false' : 'true');
    menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    menuToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    if (open) menuClose.focus(); else menuToggle.focus();
  };

  if (menuToggle && sideMenu && menuOverlay) {
    menuToggle.addEventListener('click', function () {
      setMenuOpen(!sideMenu.classList.contains('is-open'));
    });
    if (menuClose) menuClose.addEventListener('click', function () { setMenuOpen(false); });
    menuOverlay.addEventListener('click', function () { setMenuOpen(false); });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && sideMenu.classList.contains('is-open')) setMenuOpen(false);
    });
    sideMenu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () { setMenuOpen(false); });
    });
  }

  // Subtle entrance animations for commerce cards and sections.
  const revealTargets = document.querySelectorAll(
    '.service-strip article, .category-card, .product-card, .commerce-banner, .featured-products .section-heading, .shop-categories .section-heading'
  );

  if ('IntersectionObserver' in window && revealTargets.length) {
    document.documentElement.classList.add('motion-ready');
    revealTargets.forEach(function (element) {
      element.classList.add('reveal');
    });

    const revealObserver = new IntersectionObserver(function (entries, observer) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -20px 0px' });

    revealTargets.forEach(function (element) {
      revealObserver.observe(element);
    });
  }
})();
