/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
/*
 * Поліпшення для сторінок Security Guard. Без цього файлу все працює:
 * графіки намальовані на сервері (з рідними підказками <title>), форми —
 * звичайні POST. Тут лише: гарні підказки, підтвердження, друк,
 * блокування кнопки під час довгої дії, підстановка IP у поле.
 * Жодних inline-обробників; дані з атакуючих запитів — лише через textContent.
 */
(function () {
  'use strict';

  function each(list, fn) {
    Array.prototype.forEach.call(list, fn);
  }

  function initTooltips(root) {
    each(root.querySelectorAll('.sg-chart'), function (chart) {
      var svg = chart.querySelector('svg');
      if (!svg) {
        return;
      }
      var tip = document.createElement('div');
      tip.className = 'sg-tip';
      tip.setAttribute('role', 'status');
      chart.appendChild(tip);
      var vb = (svg.getAttribute('viewBox') || '0 0 860 220').split(/\s+/);
      var vbW = parseFloat(vb[2]) || 860;

      function show(rect) {
        var scale = svg.getBoundingClientRect().width / vbW;
        tip.textContent = rect.getAttribute('data-sg-tip') || '';
        tip.style.left = (parseFloat(rect.getAttribute('data-sg-x')) * scale) + 'px';
        tip.style.top = (parseFloat(rect.getAttribute('data-sg-y')) * scale) + 'px';
        tip.classList.add('sg-tip-on');
      }

      function hide() {
        tip.classList.remove('sg-tip-on');
      }

      each(svg.querySelectorAll('[data-sg-tip]'), function (rect) {
        // Рідна підказка дублювала б нашу.
        var title = rect.querySelector('title');
        if (title) {
          rect.setAttribute('aria-label', title.textContent);
          title.parentNode.removeChild(title);
        }
        rect.addEventListener('mouseenter', function () { show(rect); });
        rect.addEventListener('mouseleave', hide);
        rect.addEventListener('touchstart', function () { show(rect); }, { passive: true });
      });
      chart.addEventListener('mouseleave', hide);
    });
  }

  function initForms(root) {
    each(root.querySelectorAll('form[data-sg-confirm]'), function (form) {
      form.addEventListener('submit', function (e) {
        if (!window.confirm(form.getAttribute('data-sg-confirm'))) {
          e.preventDefault();
        }
      });
    });
    each(root.querySelectorAll('form[data-sg-busy]'), function (form) {
      form.addEventListener('submit', function (e) {
        if (e.defaultPrevented) {
          return;
        }
        each(form.querySelectorAll('button[type="submit"]'), function (btn) {
          // Вимикаємо після відправлення, щоб значення кнопки встигло піти.
          window.setTimeout(function () {
            btn.disabled = true;
            btn.textContent = form.getAttribute('data-sg-busy');
          }, 0);
        });
      });
    });
  }

  function initButtons(root) {
    each(root.querySelectorAll('[data-sg-print]'), function (btn) {
      btn.addEventListener('click', function () { window.print(); });
    });
    each(root.querySelectorAll('[data-sg-fill]'), function (btn) {
      btn.addEventListener('click', function () {
        var target = document.querySelector(btn.getAttribute('data-sg-fill'));
        if (target) {
          target.value = btn.getAttribute('data-sg-value') || '';
          target.focus();
        }
      });
    });
  }

  function init() {
    var roots = document.querySelectorAll('.sg-page');
    each(roots, function (root) {
      initTooltips(root);
      initForms(root);
      initButtons(root);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}());
