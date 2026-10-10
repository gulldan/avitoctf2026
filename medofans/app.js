const $ = (s) => document.querySelector(s);

const FALLBACK_IMG = '/assets/badger.svg';

const GALLERY = [
  '/assets/gallery/1.jpg',
  '/assets/gallery/2.jpg',
  '/assets/gallery/3.jpg',
  '/assets/gallery/4.jpg',
  '/assets/gallery/5.jpg',
  '/assets/gallery/6.jpg',
];

function setSpinner(on) {
  $('#spinner').style.display = on ? 'flex' : 'none';
  $('#content').style.display = on ? 'none' : 'block';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : s;
  return d.innerHTML;
}

function withFallback(img) {
  img.onerror = function () {
    this.onerror = null;
    this.src = FALLBACK_IMG;
  };
  return img;
}

function render(data) {
  const t = data.translations || {};
  document.querySelectorAll('[data-t]').forEach((el) => {
    if (t[el.dataset.t] !== undefined) el.textContent = t[el.dataset.t];
  });
  if (t.site_title) document.title = t.site_title;

  const wrap = $('#facts');
  wrap.innerHTML = '';
  (data.facts || []).forEach((f) => {
    const col = document.createElement('div');
    col.className = 'column is-12-mobile is-half-tablet is-one-third-desktop';
    const src = (typeof f.image === 'string' && f.image) ? f.image : FALLBACK_IMG;
    col.innerHTML =
      '<div class="card fact-card">' +
        '<div class="card-image"><figure class="image is-4by3">' +
          '<img class="fact-img" alt="' + esc(f.title) + '"></figure></div>' +
        '<div class="card-content">' +
          '<p class="title is-5">' + esc(f.title) + '</p>' +
          '<p>' + esc(f.body) + '</p>' +
        '</div>' +
      '</div>';
    const img = withFallback(col.querySelector('.fact-img'));
    img.src = src;
    wrap.appendChild(col);
  });
}

function renderGallery() {
  const wrap = $('#gallery');
  if (!wrap) return;
  wrap.innerHTML = '';
  GALLERY.forEach((path, i) => {
    const col = document.createElement('div');
    col.className = 'column is-12-mobile is-half-tablet is-one-third-desktop';
    col.innerHTML =
      '<div class="card gallery-card">' +
        '<div class="card-image"><figure class="image is-4by3">' +
          '<img class="gallery-img" alt="Honey badger photo ' + (i + 1) + '"></figure></div>' +
      '</div>';
    const img = withFallback(col.querySelector('.gallery-img'));
    img.src = path;
    wrap.appendChild(col);
  });
}

function showSection(name) {
  document.querySelectorAll('.page-section').forEach((sec) => {
    sec.hidden = sec.dataset.section !== name;
  });
  document.querySelectorAll('[data-nav]').forEach((link) => {
    link.classList.toggle('is-active', link.dataset.nav === name);
  });
}

async function load(lang) {
  $('#lang-label').textContent = lang.toUpperCase() + ' ▾';
  $('#error').style.display = 'none';
  setSpinner(true);
  try {
    const r = await fetch('/api/content.php?lang=' + encodeURIComponent(lang));
    const data = await r.json();
    if (!r.ok || data.error) throw new Error(data.error || ('HTTP ' + r.status));
    render(data);
  } catch (e) {
    $('#error').style.display = 'block';
    $('#error .message-body').textContent = e.message;
  } finally {
    setSpinner(false);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const burger = $('.navbar-burger');
  const menu = $('#mainNav');
  const langDrop = $('#lang-dropdown');
  const langLabel = $('#lang-label');

  const closeMenu = () => {
    if (burger) burger.classList.remove('is-active');
    if (menu) menu.classList.remove('is-active');
  };
  const closeLang = () => langDrop && langDrop.classList.remove('is-active');

  if (burger && menu) {
    burger.addEventListener('click', () => {
      burger.classList.toggle('is-active');
      menu.classList.toggle('is-active');
    });
  }

  if (langLabel && langDrop) {
    langLabel.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      langDrop.classList.toggle('is-active');
    });
  }

  document.querySelectorAll('[data-lang]').forEach((b) =>
    b.addEventListener('click', () => {
      load(b.dataset.lang);
      closeLang();
      closeMenu();
    }));

  document.querySelectorAll('[data-nav]').forEach((link) =>
    link.addEventListener('click', () => {
      showSection(link.dataset.nav);
      closeMenu();
    }));

  document.addEventListener('click', (e) => {
    if (langDrop && !langDrop.contains(e.target)) closeLang();
  });

  renderGallery();
  showSection('facts');
  load('en');
});
