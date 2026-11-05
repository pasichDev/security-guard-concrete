#!/usr/bin/env bash
# Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.
#
# Встановлення або оновлення пакета Security Guard на сервері одним кроком.
# Запускати в терміналі хостингу (cPanel → Terminal або SSH):
#
#   bash server-update.sh                 # найновіший тег версії vX.Y.Z
#   bash server-update.sh v1.2.0          # конкретний тег (гілка чи коміт — з попередженням)
#   EXPECTED_SHA=<коміт> bash server-update.sh v1.2.0   # відмовитись, якщо коміт інший
#
# Що робить:
#   1. забирає код із репозиторію в ~/repositories/security-guard-concrete, показує коміт,
#      звіряє його з EXPECTED_SHA і, якщо тег підписаний і є gpg, перевіряє підпис;
#   2. перевіряє синтаксис PHP і збирає копію пакета без tests/, docs/, bin/, .git;
#   3. підміняє packages/security_guard (попередня версія — у ~/.security_guard-deploy/prev);
#   4. c5:package:install (якщо пакет не встановлений у Concrete) або c5:package:update, чистить кеш;
#   5. перевіряє, що головна сторінка відповідає.
#
# Файли повертаються лише ДО кроку з базою: якщо щось зламалося раніше або сам
# install/update завершився помилкою. Після успішного install/update файли й схема
# бази вже узгоджені, тож невдала перевірка сайту лише попереджає (код виходу 3).
#
# Змінні середовища:
#   SITE_ROOT       корінь сайту Concrete        (за замовчуванням ~/public_html)
#   PHP             інтерпретатор PHP             (alt-php 8.2 cPanel, якщо є, інакше php)
#   SITE_URL        адреса для перевірки          (за замовчуванням — канонічна адреса з Concrete)
#   REPO_URL        репозиторій                   (публічний репозиторій пакета)
#   EXPECTED_SHA    очікуваний коміт (повний або щонайменше 7 символів)
#   REQUIRE_SIGNED  1 — вимагати перевірений підпис тегу (інакше непідтверджений підпис лише попереджає)
#
# Коди виходу: 0 — готово; 1 — помилка (файли повернуто, якщо їх встигли підмінити);
# 2 — уже виконується інший запуск; 3 — встановлено, але перевірка сайту не пройшла.
set -euo pipefail

REF="${1:-}"
SITE_ROOT="${SITE_ROOT:-$HOME/public_html}"
REPO_URL="${REPO_URL:-https://github.com/pasichDev/security-guard-concrete.git}"
SRC="${HOME}/repositories/security-guard-concrete"
PKG_DIR="${SITE_ROOT}/packages/security_guard"
WORK="${HOME}/.security_guard-deploy"
STAGE="${WORK}/new"
PREV="${WORK}/prev"
LOCK="${WORK}/lock"
if [ -z "${PHP:-}" ]; then
  if [ -x /opt/alt/php82/usr/bin/php ]; then PHP=/opt/alt/php82/usr/bin/php; else PHP=php; fi
fi
C5=("$PHP" "${SITE_ROOT}/concrete/bin/concrete5")

warn() { echo "! $*" >&2; }
die() { echo "✗ $*" >&2; exit 1; }

[ -f "${SITE_ROOT}/concrete/bin/concrete5" ] || die "Не знайдено Concrete у ${SITE_ROOT}"
mkdir -p "${WORK}"

# ---- Блокування: каталог створюється атомарно; застарілий (процес завершився) прибирається.
PHASE=init
HAVE_LOCK=0
HAD_PREV=0
if ! mkdir "${LOCK}" 2>/dev/null; then
  OTHER="$(cat "${LOCK}/pid" 2>/dev/null || true)"
  if [ -n "${OTHER}" ] && kill -0 "${OTHER}" 2>/dev/null; then
    echo "✗ Уже виконується інший запуск (PID ${OTHER}). Якщо це не так — видаліть ${LOCK}" >&2
    exit 2
  fi
  warn "застаріле блокування (PID ${OTHER:-?}) — прибираю"
  rm -rf "${LOCK}"
  mkdir "${LOCK}" 2>/dev/null || { echo "✗ Уже виконується інший запуск" >&2; exit 2; }
fi
echo "$$" > "${LOCK}/pid"
HAVE_LOCK=1

# Повернення файлів — лише поки база не чіпалася (PHASE=swapped).
restore_files() {
  if [ "${HAD_PREV}" = 1 ] && [ -d "${PREV}" ]; then
    echo "  повертаю попередню версію файлів" >&2
    rm -rf "${PKG_DIR}"
    mv "${PREV}" "${PKG_DIR}"
  elif [ "${HAD_PREV}" = 0 ]; then
    echo "  попередньої версії не було — прибираю щойно скопійовані файли" >&2
    rm -rf "${PKG_DIR}"
  fi
  "${C5[@]}" c5:clear-cache >/dev/null 2>&1 || true
}
on_exit() {
  local code=$?
  set +e
  if [ "${PHASE}" = swapped ]; then
    echo "✗ перервано до завершення кроку з базою (код ${code})" >&2
    restore_files
    [ "${code}" = 0 ] && code=1
  fi
  rm -rf "${STAGE}"
  [ "${HAVE_LOCK}" = 1 ] && rm -rf "${LOCK}"
  exit "${code}"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

# ---- Код
if [ -d "${SRC}/.git" ]; then
  CURRENT_URL="$(git -C "${SRC}" remote get-url origin 2>/dev/null || true)"
  if [ -z "${CURRENT_URL}" ]; then
    git -C "${SRC}" remote add origin "${REPO_URL}"
  elif [ "${CURRENT_URL}" != "${REPO_URL}" ]; then
    warn "origin копії був ${CURRENT_URL}, змінюю на ${REPO_URL}"
    git -C "${SRC}" remote set-url origin "${REPO_URL}"
  fi
  git -C "${SRC}" fetch --quiet --force --prune --tags origin '+refs/heads/*:refs/remotes/origin/*'
else
  mkdir -p "$(dirname "${SRC}")"
  git clone --quiet "${REPO_URL}" "${SRC}"
  git -C "${SRC}" fetch --quiet --force --tags origin
fi

IS_TAG=0
if [ -z "${REF}" ]; then
  # Найновіша версія за semver серед тегів vX.Y.Z — не гілка main.
  ALL_REFS="$(git -C "${SRC}" for-each-ref --format='%(refname:strip=2)' refs/tags)"
  REF="$(echo "${ALL_REFS}" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
  [ -n "${REF}" ] || die "У репозиторії немає тегів версій vX.Y.Z — вкажіть ref явно"
fi
if git -C "${SRC}" rev-parse --verify --quiet "refs/tags/${REF}" >/dev/null; then
  IS_TAG=1
  TARGET="refs/tags/${REF}"
elif git -C "${SRC}" rev-parse --verify --quiet "refs/remotes/origin/${REF}" >/dev/null; then
  warn "${REF} — гілка, а не тег версії: розгортається її поточний стан"
  TARGET="refs/remotes/origin/${REF}"
elif git -C "${SRC}" rev-parse --verify --quiet "${REF}^{commit}" >/dev/null; then
  warn "${REF} — коміт, а не тег версії"
  TARGET="${REF}"
else
  die "Не знайдено тег, гілку чи коміт ${REF}"
fi
SHA="$(git -C "${SRC}" rev-parse "${TARGET}^{commit}")"
echo "→ код: ${REPO_URL} @ ${REF}"
echo "  коміт ${SHA}"

if [ -n "${EXPECTED_SHA:-}" ]; then
  case "${EXPECTED_SHA}" in
    *[!0-9a-fA-F]*) die "EXPECTED_SHA має бути шістнадцятковим" ;;
  esac
  [ "${#EXPECTED_SHA}" -ge 7 ] || die "EXPECTED_SHA закороткий (потрібно щонайменше 7 символів)"
  WANT="$(echo "${EXPECTED_SHA}" | tr 'A-F' 'a-f')"
  case "${SHA}" in
    "${WANT}"*) echo "  коміт збігається з EXPECTED_SHA" ;;
    *) die "коміт ${SHA} не збігається з EXPECTED_SHA=${EXPECTED_SHA} — розгортання скасовано" ;;
  esac
fi

VERIFIED=0
if [ "${IS_TAG}" = 1 ] && [ "$(git -C "${SRC}" cat-file -t "${TARGET}")" = tag ]; then
  TAG_OBJECT="$(git -C "${SRC}" cat-file -p "${TARGET}")"
  case "${TAG_OBJECT}" in
    *"-----BEGIN PGP SIGNATURE-----"*|*"-----BEGIN SSH SIGNATURE-----"*)
      # Перевірка підпису залежить від сервера: потрібні gpg з ключем автора (PGP) або
      # OpenSSH 8.2+ і gpg.ssh.allowedSignersFile (SSH). Якщо перевірити нічим, це не
      # привід зупиняти деплой: точну версію прив'язує EXPECTED_SHA. Обов'язковою
      # перевірка стає лише з REQUIRE_SIGNED=1.
      if VERIFY_OUT="$(git -C "${SRC}" verify-tag "${REF}" 2>&1)"; then
        VERIFIED=1
        echo "  підпис тегу перевірено"
      else
        echo "  ! тег підписаний, але підпис не вдалося перевірити на цьому сервері:"
        echo "${VERIFY_OUT}" | tail -2 | sed 's/^/      /'
        if [ -z "${EXPECTED_SHA:-}" ]; then
          echo "  ! задайте EXPECTED_SHA=<коміт тегу>, щоб прив'язати версію"
        fi
      fi
      ;;
    *) echo "  тег без підпису" ;;
  esac
fi
if [ "${REQUIRE_SIGNED:-0}" = 1 ] && [ "${VERIFIED}" != 1 ]; then
  die "REQUIRE_SIGNED=1, а перевіреного підпису тегу немає"
fi

git -C "${SRC}" checkout --quiet --detach "${SHA}"
VERSION="$(sed -n "s/.*pkgVersion = '\([^']*\)'.*/\1/p" "${SRC}/controller.php")"
echo "  версія пакета ${VERSION}"

echo "→ перевірка синтаксису PHP"
# Без process substitution: на CageFS-хостингах немає /dev/fd.
LINT_FAILED="$(find "${SRC}" -name '*.php' -not -path '*/tests/*' -not -path '*/.git/*' \
  -exec sh -c 'for f do "$0" -l "$f" >/dev/null 2>&1 || echo "$f"; done' "$PHP" {} +)"
if [ -n "${LINT_FAILED}" ]; then
  echo "Синтаксичні помилки:" >&2
  echo "${LINT_FAILED}" >&2
  exit 1
fi

# ---- Чи встановлений пакет у Concrete (а не лише чи є файли).
CHECK="${WORK}/is-installed.php"
cat > "${CHECK}" <<'PHPCHECK'
<?php
$app = \Concrete\Core\Support\Facade\Application::getFacadeApplication();
$pkg = $app->make(\Concrete\Core\Package\PackageService::class)->getByHandle('security_guard');
echo ($pkg && $pkg->isPackageInstalled()) ? "SG_STATE=installed\n" : "SG_STATE=absent\n";
PHPCHECK
STATE_OUT="$("${C5[@]}" c5:exec "${CHECK}" 2>&1 || true)"
case "${STATE_OUT}" in
  *SG_STATE=installed*) DB_INSTALLED=1 ;;
  *SG_STATE=absent*) DB_INSTALLED=0 ;;
  *) die "Не вдалося визначити, чи встановлений пакет: ${STATE_OUT}" ;;
esac

# Тимчасові й попередні копії — поза packages/: Concrete сканує цю теку, і друга
# тека з тим самим класом контролера зламала б сторінку «Extend Concrete».
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
# Лише те, що потрібно сайту: без тестів, документації, скриптів і git.
for item in LICENSE controller.php db.xml controllers css elements js languages single_pages src; do
  if [ -e "${SRC}/${item}" ]; then cp -a "${SRC}/${item}" "${STAGE}/"; fi
done

echo "→ підміна файлів пакета"
rm -rf "${PREV}"
PHASE=swapped
if [ -e "${PKG_DIR}" ]; then
  HAD_PREV=1
  mv "${PKG_DIR}" "${PREV}"
fi
mkdir -p "$(dirname "${PKG_DIR}")"
# mv у наявний каталог поклав би пакет усередину нього.
[ ! -e "${PKG_DIR}" ] || rm -rf "${PKG_DIR}"
mv "${STAGE}" "${PKG_DIR}"

if [ "${DB_INSTALLED}" = 1 ]; then
  echo "→ c5:package:update"
  OUT="$("${C5[@]}" c5:package:update security_guard 2>&1)" || { echo "${OUT}" >&2; die "оновлення не вдалося"; }
else
  echo "→ c5:package:install (режим спостереження)"
  OUT="$("${C5[@]}" c5:package:install security_guard 2>&1)" || { echo "${OUT}" >&2; die "встановлення не вдалося"; }
fi
echo "${OUT}" | tail -n 2
# Далі файли не повертаються: схема бази вже відповідає новим файлам.
PHASE=db_done

"${C5[@]}" c5:clear-cache >/dev/null 2>&1 || warn "c5:clear-cache не вдалося — очистіть кеш вручну"

normalize_url() {
  local v
  v="$(echo "$1" | tr -d '[:space:]' | sed -e 's/^"//' -e 's/"$//')"
  case "${v}" in
    http://*|https://*) echo "${v%/}" ;;
    *) echo "" ;;
  esac
}
if [ -n "${SITE_URL:-}" ]; then
  URL="$(normalize_url "${SITE_URL}")"
else
  # Не задана канонічна адреса друкується як "null" — таке значення не адреса.
  URL="$(normalize_url "$("${C5[@]}" c5:config get site.sites.default.seo.canonical_url 2>/dev/null || true)")"
fi

STATUS=0
if [ -z "${URL}" ]; then
  warn "адресу сайту не визначено (канонічна адреса не задана) — перевірку головної пропущено; задайте SITE_URL=https://…"
elif ! command -v curl >/dev/null 2>&1; then
  warn "curl немає — перевірку головної пропущено"
else
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${URL}/" || true)"
  echo "→ перевірка ${URL}/: HTTP ${CODE}"
  case "${CODE}" in
    2??|3??) ;;
    *)
      echo "!!! УВАГА: сайт відповідає HTTP ${CODE} після оновлення." >&2
      echo "!!! Файли НЕ повертаються: база вже оновлена під версію ${VERSION}." >&2
      echo "!!! Перевірте сайт і журнал помилок; попередня версія файлів: ${PREV}" >&2
      STATUS=3
      ;;
  esac
fi

echo "✓ Security Guard ${VERSION} (${SHA}) встановлено."
if [ "${HAD_PREV}" = 1 ]; then
  echo "  Попередня версія файлів: ${PREV} (зміни бази не відкочуються — для цього бекап)."
fi
exit "${STATUS}"
