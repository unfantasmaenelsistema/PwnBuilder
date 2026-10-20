/* app.js — motor e interfaz de PwnBuilder (Un Fantasma en el Sistema, MIT)
 * Arma el comando de la herramienta elegida en directo. Todo en el navegador;
 * solo idioma, tema y última herramienta van a localStorage. No ejecuta nada. */
(function () {
  'use strict';
  var TOOLS = PWN_TOOLS.TOOLS, CATS = PWN_TOOLS.CATS;
  var byId = {}; TOOLS.forEach(function (t) { byId[t.id] = t; });

  var UI = {
    es: {
      title: 'PwnBuilder', tagline: 'Generador de comandos para pentesting y CTF',
      lead: 'Monta el comando de 42 herramientas de Kali marcando opciones, sin memorizar banderas. Ves el comando en directo y lo copias a tu terminal.',
      ethics: '⚖️ <b>Uso responsable.</b> Son herramientas ofensivas reales. PwnBuilder solo escribe el texto del comando: no ejecuta nada. Úsalas únicamente sobre sistemas y redes propios o con autorización por escrito (pentest, CTF, laboratorio). El acceso no autorizado es delito.',
      search: 'Buscar herramienta…', choose: 'Elige una herramienta para empezar.',
      command: 'Comando', copy: 'Copiar', copied: '¡Copiado!', incomplete: 'Rellena los campos obligatorios (marcados con ‹…›).',
      fLocal: 'Todo funciona en tu navegador', themeTitle: 'Cambiar tema', langTitle: 'English', noResults: 'Sin resultados.'
    },
    en: {
      title: 'PwnBuilder', tagline: 'Command generator for pentesting and CTF',
      lead: 'Build the command for 42 Kali tools by ticking options, without memorising flags. See the command live and copy it to your terminal.',
      ethics: '⚖️ <b>Responsible use.</b> These are real offensive tools. PwnBuilder only writes the command text: it runs nothing. Use them only on systems and networks you own or are authorised to test in writing (pentest, CTF, lab). Unauthorised access is a crime.',
      search: 'Search tool…', choose: 'Pick a tool to start.',
      command: 'Command', copy: 'Copy', copied: 'Copied!', incomplete: 'Fill in the required fields (marked ‹…›).',
      fLocal: 'Everything runs in your browser', themeTitle: 'Toggle theme', langTitle: 'Español', noResults: 'No results.'
    }
  };

  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
  var lang = store('pwn-lang') || ((navigator.language || 'es').slice(0, 2) === 'es' ? 'es' : 'en');
  if (!UI[lang]) lang = 'es';
  function t(k) { var s = UI[lang][k]; return s === undefined ? UI.es[k] : s; }
  function tl(obj) { return obj ? (obj[lang] || obj.es) : ''; }
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

  function shq(s) {
    if (s === '') return "''";
    if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }

  var current = null;

  function helper(tool) {
    var fmap = {}; tool.fields.forEach(function (f) { if (f.id) fmap[f.id] = f; });
    return {
      v: function (id) { var el = $('fld_' + id); return el ? el.value.trim() : ''; },
      c: function (id) { var el = $('fld_' + id); return el ? el.checked : false; },
      q: shq,
      field: function (id) { return fmap[id]; }
    };
  }

  function assemble(tool, v) {
    var parts = [tool.bin], inc = false;
    tool.fields.forEach(function (f) {
      if (f.k === 'head') return;
      if (f.k === 'flag') { if (v.c(f.id)) parts.push(f.flag); return; }
      var val = v.v(f.id);
      if (!val) {
        if (f.req) { inc = true; parts.push((f.flag && !f.glue ? f.flag + ' ' : (f.flag || '')) + '‹' + (tl(f.l) || f.id) + '›'); }
        return;
      }
      var token = f.raw ? val : shq(val);
      parts.push(!f.flag ? token : (f.glue ? f.flag + token : f.flag + ' ' + token));
    });
    return { cmd: parts.join(' '), incomplete: inc };
  }

  function rebuild() {
    if (!current) return;
    var v = helper(current);
    var r = current.build ? current.build(v) : assemble(current, v);
    $('cmd').textContent = r.cmd;
    $('copyBtn').disabled = !!r.incomplete;
    $('incNote').hidden = !r.incomplete;
  }

  function renderForm(tool) {
    current = tool;
    store('pwn-last', tool.id);
    var h = '<div class="tool-head"><h2>' + esc(tool.name) + '</h2><span class="catpill">' + esc(tl(CATS[tool.cat])) + '</span></div>' +
      '<p class="tool-desc">' + esc(tl(tool.d)) + '</p><form id="toolForm" autocomplete="off" onsubmit="return false"><div class="fgrid">';
    tool.fields.forEach(function (f) {
      if (f.k === 'head') { h += '<div class="fhead">' + esc(tl(f.l)) + '</div>'; return; }
      if (f.k === 'flag') {
        h += '<label class="fopt"><input type="checkbox" id="fld_' + f.id + '"><span>' + esc(tl(f.l)) + '</span></label>';
        return;
      }
      if (f.k === 'select') {
        h += '<label class="ffield"><span>' + esc(tl(f.l)) + '</span><select id="fld_' + f.id + '">' +
          f.opts.map(function (o) { return '<option value="' + esc(o.v) + '">' + esc(tl(o.l) || o.l) + '</option>'; }).join('') + '</select></label>';
        return;
      }
      var type = f.k === 'num' ? 'number' : 'text';
      h += '<label class="ffield' + (f.req ? ' req' : '') + '"><span>' + esc(tl(f.l)) + '</span>' +
        '<input type="' + type + '" id="fld_' + f.id + '" spellcheck="false" placeholder="' + esc(f.ph || '') + '"></label>';
    });
    h += '</div></form>';
    $('panel').innerHTML = h;
    rebuild();
  }

  // Lista de herramientas agrupada por categoría, con buscador
  function renderList(filter) {
    filter = (filter || '').toLowerCase();
    var html = '', any = false;
    Object.keys(CATS).forEach(function (cat) {
      var catMatch = tl(CATS[cat]).toLowerCase().indexOf(filter) > -1;
      var tools = TOOLS.filter(function (t) { return t.cat === cat; }).filter(function (t) {
        return !filter || catMatch || t.name.toLowerCase().indexOf(filter) > -1 || t.id.indexOf(filter) > -1 || tl(t.d).toLowerCase().indexOf(filter) > -1;
      });
      if (!tools.length) return;
      any = true;
      html += '<div class="cat"><h3>' + esc(tl(CATS[cat])) + '</h3><div class="toolbtns">' +
        tools.map(function (t) {
          return '<button class="toolbtn' + (current && current.id === t.id ? ' active' : '') + '" data-tool="' + t.id + '" title="' + esc(tl(t.d)) + '">' + esc(t.name) + '</button>';
        }).join('') + '</div></div>';
    });
    $('toolList').innerHTML = any ? html : '<p class="note">' + t('noResults') + '</p>';
  }

  $('toolList').addEventListener('click', function (e) {
    var b = e.target.closest('[data-tool]'); if (!b) return;
    renderForm(byId[b.dataset.tool]);
    renderList($('search').value);
    if (window.matchMedia('(max-width:860px)').matches) $('panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  $('search').addEventListener('input', function () { renderList(this.value); });
  document.addEventListener('input', function (e) { if (e.target.closest('#toolForm')) rebuild(); });
  document.addEventListener('change', function (e) { if (e.target.closest('#toolForm')) rebuild(); });

  $('copyBtn').addEventListener('click', function () {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText($('cmd').textContent).then(function () {
      var b = $('copyBtn'); b.textContent = t('copied'); setTimeout(function () { b.textContent = t('copy'); }, 1500);
    });
  });

  function applyI18n() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(function (el) { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelector('[data-i18n-html="lead"]').innerHTML = t('lead');
    document.querySelector('[data-i18n-html="ethics"]').innerHTML = t('ethics');
    $('search').placeholder = t('search');
    $('langToggle').textContent = lang === 'es' ? 'EN' : 'ES'; $('langToggle').title = t('langTitle');
    $('themeToggle').title = t('themeTitle');
    renderList($('search').value);
    if (current) renderForm(current); else $('panel').innerHTML = '<p class="choose">' + t('choose') + '</p>';
  }
  function syncTheme() { $('themeToggle').textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? '☀' : '☾'; }
  $('langToggle').addEventListener('click', function () { lang = lang === 'es' ? 'en' : 'es'; store('pwn-lang', lang); applyI18n(); });
  $('themeToggle').addEventListener('click', function () {
    var n = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', n); store('pwn-theme', n); syncTheme();
  });

  syncTheme();
  var last = store('pwn-last');
  if (last && byId[last]) current = byId[last];
  applyI18n();

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () { navigator.serviceWorker.register('sw.js').catch(function () {}); });
  }
})();
