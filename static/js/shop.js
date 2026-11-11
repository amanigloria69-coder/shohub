// Stage 2: live cart (AJAX), add-to-cart, product image preview.
(function () {
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrf = meta ? meta.content : '';

  function toast(message, type) {
    const box = document.getElementById('toasts');
    if (!box) return;
    const t = document.createElement('div');
    t.className = 'toast' + (type === 'error' ? ' error' : '');
    t.textContent = message;
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 3500);
  }

  function setCount(n) {
    const el = document.getElementById('cartCount');
    if (!el) return;
    el.textContent = n;
    el.hidden = !n;
    const link = el.closest('.cart-link');
    if (link) { link.classList.remove('bump'); void link.offsetWidth; link.classList.add('bump'); }
  }

  async function post(url, data) {
    const body = new URLSearchParams(Object.assign({ csrf: csrf }, data));
    try {
      const res = await fetch(url, {
        method: 'POST', body: body,
        headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' }
      });
      if (res.redirected) { window.location.href = res.url; return null; }  // session expired / not allowed
      return await res.json();
    } catch (err) {
      toast('Network problem. Please try again.', 'error');
      return null;
    }
  }

  // ---- Add to cart (catalog + product page) ----
  document.querySelectorAll('form.add-form').forEach(function (form) {
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      const btn = form.querySelector('button');
      btn.disabled = true;
      const j = await post(form.action, { product_id: form.product_id.value });
      if (j) {
        toast(j.message, j.ok ? 'success' : 'error');
        if (j.count !== undefined) setCount(j.count);
      }
      btn.disabled = false;
    });
  });

  // ---- Cart page: live quantity changes ----
  const table = document.getElementById('cartTable');
  if (table) {
    const grand = document.getElementById('grandTotal');
    const itemCount = document.getElementById('itemCount');

    function syncButtons(row) {
      const input = row.querySelector('.qty-input');
      const q = parseInt(input.value, 10) || 1;
      const stock = parseInt(row.dataset.stock, 10);
      row.querySelector('.minus').disabled = q <= 1;
      row.querySelector('.plus').disabled = q >= stock;
      row.querySelector('.warn').hidden = q <= stock;
    }

    function applyTotals(j) {
      if (j.total_fmt) grand.textContent = j.total_fmt;
      if (j.count !== undefined) { itemCount.textContent = j.count; setCount(j.count); }
    }

    async function changeQty(row, qty) {
      const input = row.querySelector('.qty-input');
      const j = await post(table.dataset.updateUrl, { product_id: row.dataset.id, quantity: qty });
      if (!j) return;
      if (!j.ok) toast(j.message, 'error');
      if (j.quantity !== undefined) {
        input.value = j.quantity;
        row.dataset.stock = j.stock;
        input.max = j.stock;
        row.querySelector('.subtotal').textContent = j.subtotal_fmt;
      }
      applyTotals(j);
      syncButtons(row);
    }

    table.querySelectorAll('.cart-row').forEach(function (row) {
      const input = row.querySelector('.qty-input');
      syncButtons(row);
      row.querySelector('.minus').addEventListener('click', function () {
        changeQty(row, (parseInt(input.value, 10) || 1) - 1);
      });
      row.querySelector('.plus').addEventListener('click', function () {
        changeQty(row, (parseInt(input.value, 10) || 0) + 1);
      });
      input.addEventListener('change', function () {
        changeQty(row, parseInt(input.value, 10));
      });
      row.querySelector('.remove-form').addEventListener('submit', async function (ev) {
        ev.preventDefault();
        const j = await post(table.dataset.removeUrl, { product_id: row.dataset.id });
        if (!j) return;
        toast(j.message, j.ok ? 'success' : 'error');
        applyTotals(j);
        if (j.count === 0) { window.location.reload(); return; }
        row.classList.add('removing');
        setTimeout(function () { row.remove(); }, 250);
      });
    });
  }

  // ---- Product form: image preview + size check ----
  const imageInput = document.getElementById('imageInput');
  const preview = document.getElementById('imagePreview');
  if (imageInput && preview) {
    imageInput.addEventListener('change', function () {
      const f = imageInput.files[0];
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) {
        alert('The image is too large. Maximum size is 2 MB.');
        imageInput.value = '';
        return;
      }
      preview.src = URL.createObjectURL(f);
      preview.hidden = false;
    });
  }
})();

// ---- Checkout page: payment method panels + double-submit protection ----
(function () {
  const radios = document.querySelectorAll('input[name="payment"]');
  if (radios.length) {
    const sync = function () {
      const chosen = document.querySelector('input[name="payment"]:checked');
      const value = chosen ? chosen.value : '';
      document.querySelectorAll('.pay-detail').forEach(function (d) { d.hidden = d.dataset.for !== value; });
      const momo = document.querySelector('input[name="momo"]');
      if (momo) momo.required = value === 'momo';
      document.querySelectorAll('.pay-opt').forEach(function (l) {
        l.classList.toggle('selected', l.querySelector('input').checked);
      });
    };
    radios.forEach(function (r) { r.addEventListener('change', sync); });
    sync();
  }
  const form = document.getElementById('checkoutForm');
  if (form) {
    form.addEventListener('submit', function () {
      const btn = document.getElementById('placeOrder');
      btn.disabled = true;
      btn.textContent = 'Placing your order...';
    });
  }
})();
