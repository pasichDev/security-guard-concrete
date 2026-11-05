#!/usr/bin/env bash
# Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.
#
# Встановлення або оновлення пакета Security Guard на сервері одним кроком.
# Запускати в терміналі хостингу (cPanel → Terminal або SSH):
#
#   bash server-update.sh            # остання версія з гілки main
#   bash server-update.sh v1.1.0     # конкретний тег або коміт
#
# Що робить:
#   1. забирає код із публічного репозиторію в ~/repositories/security-guard-concrete;
#   2. збирає копію пакета без tests/, docs/, bin/, .git у тимчасовій теці поруч;
#   3. підміняє packages/security_guard (попередня версія — у ~/.security_guard-deploy/prev);
#   4. виконує c5:package:install (перший раз) або c5:package:update і чистить кеш;
#   5. перевіряє, що головна сторінка відповідає; якщо ні — повертає попередню версію.
#
# Налаштування через змінні середовища:
#   SITE_ROOT  корінь сайту Concrete       (за замовчуванням ~/public_html)
#   PHP        інтерпретатор PHP            (за замовчуванням alt-php 8.2 cPanel, якщо є, інакше php)
#   SITE_URL   адреса для перевірки         (за замовчуванням береться з налаштувань Concrete)
#   REPO_URL   репозиторій                  (за замовчуванням публічний репозиторій пакета)
set -euo pipefail

REF="${1:-main}"
SITE_ROOT="${SITE_ROOT:-$HOME/public_html}"
REPO_URL="${REPO_URL:-https://github.com/pasichDev/security-guard-concrete.git}"
SRC="${HOME}/repositories/security-guard-concrete"
PKG_DIR="${SITE_ROOT}/packages/security_guard"
if [ -z "${PHP:-}" ]; then
  if [ -x /opt/alt/php82/usr/bin/php ]; then PHP=/opt/alt/php82/usr/bin/php; else PHP=php; fi
fi
C5=("$PHP" "${SITE_ROOT}/concrete/bin/concrete5")

[ -f "${SITE_ROOT}/concrete/bin/concrete5" ] || { echo "Не знайдено Concrete у ${SITE_ROOT}" >&2; exit 1; }

echo "→ код: ${REPO_URL} @ ${REF}"
if [ -d "${SRC}/.git" ]; then
  git -C "${SRC}" fetch --quiet --tags origin
else
  mkdir -p "$(dirname "${SRC}")"
  git clone --quiet "${REPO_URL}" "${SRC}"
fi
if git -C "${SRC}" rev-parse --verify --quiet "origin/${REF}" >/dev/null; then
  git -C "${SRC}" checkout --quiet --detach "origin/${REF}"
else
  git -C "${SRC}" checkout --quiet --detach "${REF}"
fi
COMMIT="$(git -C "${SRC}" rev-parse --short HEAD)"
VERSION="$(sed -n "s/.*pkgVersion = '\([^']*\)'.*/\1/p" "${SRC}/controller.php")"
echo "  версія ${VERSION}, коміт ${COMMIT}"

echo "→ перевірка синтаксису PHP"
# Без process substitution: на CageFS-хостингах немає /dev/fd.
LINT_FAILED="$(find "${SRC}" -name '*.php' -not -path '*/tests/*' -not -path '*/.git/*' \
  -exec sh -c 'for f do "$0" -l "$f" >/dev/null 2>&1 || echo "$f"; done' "$PHP" {} +)"
if [ -n "${LINT_FAILED}" ]; then
  echo "Синтаксичні помилки:" >&2
  echo "${LINT_FAILED}" >&2
  exit 1
fi

# Тимчасові й попередні копії — поза packages/: Concrete сканує цю теку, і друга
# тека з тим самим класом контролера зламала б сторінку «Extend Concrete».
WORK="${HOME}/.security_guard-deploy"
STAGE="${WORK}/new"
PREV="${WORK}/prev"
mkdir -p "${WORK}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
# Лише те, що потрібно сайту: без тестів, документації, скриптів і git.
for item in LICENSE controller.php db.xml controllers css elements js languages single_pages src; do
  if [ -e "${SRC}/${item}" ]; then cp -a "${SRC}/${item}" "${STAGE}/"; fi
done

echo "→ підміна файлів пакета"
INSTALLED=0
[ -d "${PKG_DIR}" ] && INSTALLED=1
rm -rf "${PREV}"
if [ "${INSTALLED}" = 1 ]; then
  mv "${PKG_DIR}" "${PREV}"
fi
mv "${STAGE}" "${PKG_DIR}"

rollback() {
  echo "✗ $1 — повертаю попередню версію" >&2
  if [ -d "${PREV}" ]; then
    rm -rf "${PKG_DIR}"
    mv "${PREV}" "${PKG_DIR}"
    "${C5[@]}" c5:clear-cache >/dev/null 2>&1 || true
  fi
  exit 1
}

if [ "${INSTALLED}" = 1 ]; then
  echo "→ c5:package:update"
  OUT="$("${C5[@]}" c5:package:update security_guard 2>&1)" || rollback "оновлення не вдалося: ${OUT}"
  echo "${OUT}" | tail -2
  if echo "${OUT}" | grep -q "is installed"; then
    # Файли були, а в Concrete пакет не встановлений.
    "${C5[@]}" c5:package:install security_guard || rollback "встановлення не вдалося"
  fi
else
  echo "→ c5:package:install (перше встановлення, режим спостереження)"
  "${C5[@]}" c5:package:install security_guard || rollback "встановлення не вдалося"
fi
"${C5[@]}" c5:clear-cache >/dev/null

if [ -z "${SITE_URL:-}" ]; then
  SITE_URL="$("${C5[@]}" c5:config get site.sites.default.seo.canonical_url 2>/dev/null | tr -d '[:space:]' || true)"
fi
if [ -n "${SITE_URL}" ] && command -v curl >/dev/null; then
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${SITE_URL%/}/" || true)"
  echo "→ перевірка ${SITE_URL%/}/: HTTP ${CODE}"
  case "${CODE}" in
    2??|3??) ;;
    *) rollback "сайт відповідає HTTP ${CODE}" ;;
  esac
else
  echo "→ адресу сайту не визначено — перевірку головної пропущено (SITE_URL=...)"
fi

echo "✓ Security Guard ${VERSION} (${COMMIT}) встановлено. Попередня версія файлів: ${PREV}"
echo "  Відкат файлів: rm -rf ${PKG_DIR} && mv ${PREV} ${PKG_DIR} (зміни бази при оновленні не відкочуються — для цього бекап)."
