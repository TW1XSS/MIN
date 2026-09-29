#!/usr/bin/env bash
# Build a sanitized public source export for another developer or a public mirror.
# It is not a claim that a release has been independently audited.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/public-export}"
case "$OUT" in
  /*) : ;;
  *) OUT="$ROOT/$OUT" ;;
esac
[ -d "$ROOT/.git" ] || { echo "Run from a Git checkout" >&2; exit 1; }
case "$OUT" in
  "$ROOT"/*) : ;;
  *) echo "Output must stay inside the repository" >&2; exit 1 ;;
esac
rm -rf "$OUT"
mkdir -p "$OUT"

# СПИСОК ИЗ GIT, а не из файловой системы. Раньше rsync копировал всё, кроме
# перечисленного deny-листом, и в экспорт попадал локальный мусор, которого
# нет в git: 47 МБ фаззинг-корпуса (fuzz/corpus/) и xcuserdata с локальным
# именем пользователя. Секрета там не было — но дыра та же, что однажды
# утащит production .onion из локально созданного файла. Теперь в экспорт
# физически не может попасть ничего, чего нет в git.
LIST="$(mktemp)"
trap 'rm -f "$LIST"' EXIT
git -C "$ROOT" ls-files -z > "$LIST"
[ -s "$LIST" ] || { echo "export-public: git ls-files returned nothing" >&2; exit 1; }

rsync -a --from0 --files-from="$LIST" --prune-empty-dirs \
  --exclude='.git/***' \
  --exclude='AGENTS.md' \
  --exclude='docs/internal/***' \
  --exclude='docs/AUDIT_METHOD.md' \
  --exclude='scripts/internal/***' \
  --exclude='.DS_Store' \
  --exclude='.shots/***' \
  --exclude='.uitest-shots/***' \
  --exclude='xcuserdata/***' \
  --exclude='DerivedData/***' \
  --exclude='Pods/***' \
  --exclude='*.xcworkspace/***' \
  --exclude='*.xcframework/***' \
  --exclude='public-export/***' \
  --exclude='target/***' \
  --exclude='backend/target/***' \
  --exclude='fuzz/corpus/***' \
  --exclude='fuzz/artifacts/***' \
  --exclude='fuzz/Cargo.lock' \
  --exclude='*.log' \
  --exclude='*.pyc' \
  --exclude='__pycache__/***' \
  --exclude='*.key' \
  --exclude='*.pem' \
  --exclude='*.p12' \
  --exclude='*.mobileprovision' \
  --exclude='*.tar.gz' \
  --exclude='*.zip' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='*.xcuserstate' \
  --exclude='Config/Local.xcconfig' \
  --exclude='scripts/local-relay.env' \
  "$ROOT/" "$OUT/"

# rsync --files-from не обходит дерево, поэтому exclude'ы на каталоги нужно
# писать с /*** - иначе 'docs/internal/' не отфильтрует файлы внутри
# (это и случилось: проверка ниже ругалась на оставшийся docs/internal).

# Пустые каталоги остаются там, где вычеркнули единственный файл, — убираем,
# иначе в экспорте валяются docs/internal/ и подобные пустышки.
find "$OUT" -type d -empty -delete

# Каждый файл экспорта обязан быть отслеживаемым в git. Это ловит утечку
# локального мусора (xcuserdata с именем пользователя, артефакты фаззинга,
# .swiftpm, DerivedData) в момент сборки экспорта, а не постфактум.
LEAKED="$(cd "$OUT" && find . -type f -print0 | sort -z \
  | tr '\0' '\n' | sed 's|^\./||' \
  | grep -vxF -f <(tr '\0' '\n' < "$LIST" | grep -v '^$') || true)"
if [ -n "$LEAKED" ]; then
    echo "export-public: refusing output: file not tracked in git: $LEAKED" >&2
    exit 1
fi

if find "$OUT" -type f \( \
    -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.tar.gz' \
    -o -name '.env' -o -name '.env.*' \
\) -print -quit | grep -q .; then
  echo "export-public: refusing output: secret-like file detected" >&2
  exit 1
fi
if [ -e "$OUT/docs/internal" ]; then
  echo "export-public: refusing output: internal docs detected" >&2
  exit 1
fi
# Проверка ПРИСУТСТВИЯ, а не только ссылок. Раньше файл мог уехать в публичную
# сборку, если кто-то случайно выбьет строку --exclude из списка: проверка ниже
# искала только упоминания, а не сам файл. AGENTS.md лежит в корне и содержит
# заметки о работе, поэтому пропуск был бы тихим.
for leaked in "$OUT/AGENTS.md" "$OUT/docs/internal" "$OUT/scripts/internal" \
              "$OUT/docs/AUDIT_METHOD.md"; do
  if [ -e "$leaked" ]; then
    echo "export-public: refusing output: internal file present: $leaked" >&2
    exit 1
  fi
done
if grep -RIlE 'docs/internal/|AGENTS\.md' "$OUT" --exclude='export-public.sh' \
    --exclude='README.md' --exclude='OPEN_SOURCE_PREPASS.md' \
    --exclude='CONTRIBUTING.md' --exclude='SECURITY.md' | grep -q .; then
  echo "export-public: refusing output: internal reference in source" >&2
  exit 1
fi
# MIN-RED-015 (A-01): проверка СОДЕРЖИМОГО, а не только имён файлов.
# Production .onion-адрес relay'а — метаданные инфраструктуры: он связывает
# проект с конкретным узлом и не должен попасть в публичный экспорт, в README
# или в issues. Шаблоны вида <...>.onion и упоминания слова onion — не секрет,
# поэтому ловим только 56-символьный v3-адрес.
if grep -RInE '[a-z2-7]{56}\.onion' "$OUT" --exclude='*.a' --exclude='*.dylib' \
    --exclude='*.png' --exclude='*.jpg' 2>/dev/null | grep -vE 'README\.md|CONTRIBUTING\.md|SECURITY\.md|OPEN_SOURCE_PREPASS\.md' | grep -q .; then
  # В рабочем checkout дефолтный relay лежит в Info.plist — это публичный
  # rendezvous, а не секрет, и он нужен, чтобы приложение работало «из коробки».
  # Для публичного зеркала он подменяется плейсхолдером: чужие сборщики должны
  # указать СВОЙ relay, а не весь мир — узел одного разработчика (MIN-RED-015).
  python3 - "$OUT" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
plist = root / "MIN" / "Info.plist"
if plist.exists():
    text = plist.read_text(encoding="utf-8")
    text = re.sub(
        r"(<key>MinRelayAddress</key>\s*<string>)[^<]*(</string>)",
        r"\1$(MIN_RELAY_ADDR)\2",
        text,
    )
    # Локальный комментарий над ключом описывает БОЕВОЙ адрес и живой checkout,
    # поэтому в публичный пакет он не годится: вырезаем, а не добавляем свой
    # поверх (иначе в экспорте оказываются оба). Затем ставим английский.
    text = re.sub(
        r"\s*<!--.*?-->\s*\n(\t*)(?=<key>MinRelayAddress</key>)",
        r"\n\1",
        text,
        flags=re.S,
    )
    text = text.replace(
        "\t<key>MinRelayAddress</key>",
        "\t<!-- Relay rendezvous address (v3 onion). The maintainer's node is\n"
        "\t     deliberately not part of the public export: set your own. Override\n"
        "\t     at build time with INFOPLIST_KEY_MinRelayAddress=... or the env var\n"
        "\t     MIN_RELAY_ADDR=... (see MinApp.relayAddress). An empty value fails\n"
        "\t     closed by design rather than sending into the void. -->\n"
        "\t<key>MinRelayAddress</key>",
        1,
    )
    plist.write_text(text, encoding="utf-8")
    print("export-public: MinRelayAddress → placeholder (задайте свой relay)")
PY
  if grep -RInE '[a-z2-7]{56}\.onion' "$OUT" --exclude='*.a' --exclude='*.dylib' \
      --exclude='*.png' --exclude='*.jpg' 2>/dev/null \
      | grep -vE 'README\.md|CONTRIBUTING\.md|SECURITY\.md|OPEN_SOURCE_PREPASS\.md' | grep -q .; then
    echo "export-public: refusing output: live .onion address survived sanitisation" >&2
    grep -RInE '[a-z2-7]{56}\.onion' "$OUT" --exclude='*.a' 2>/dev/null | head -5 >&2
    exit 1
  fi
fi
# Apple Team ID (DEVELOPMENT_TEAM) однозначно идентифицирует учётную запись
# мейнтейнера. Это персональные данные, а не настройка сборки, нужная чужому
# разработчику, поэтому по логике MinRelayAddress публичный экспорт обнуляет
# его: Xcode предложит выбрать свою команду при первом открытии проекта.
# В приватном репозитории команда остаётся как есть.
PBXPROJ="$OUT/MIN.xcodeproj/project.pbxproj"
if [ -f "$PBXPROJ" ]; then
  python3 - "$PBXPROJ" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text(encoding="utf-8")
new = re.sub(r"(DEVELOPMENT_TEAM = )[A-Z0-9]{10}(;)", r'\1""\2', text)
if new != text:
    p.write_text(new, encoding="utf-8")
    print("export-public: DEVELOPMENT_TEAM cleared (Xcode asks for a team)")
PY
  # Проверка ПОСЛЕ подстановки, а не по наличию записи в исходнике: раньше
  # утечка проходила молча, потому что проверяли только исключения из
  # deny-листа, а не результат санации.
  if grep -nE '^[[:space:]]*DEVELOPMENT_TEAM = [A-Z0-9]{10};' "$PBXPROJ" | grep -q .; then
    echo "export-public: refusing output: Apple Team ID survived sanitisation" >&2
    exit 1
  fi
  # Подстановка не должна ломать проект. Пустое значение без кавычек
  # (DEVELOPMENT_TEAM = ;) выглядит безобидно, но Xcode перестаёт открывать
  # pbxproj — а экспорт это пропускал, потому что проверял только отсутствие
  # team id, а не то, что файл вообще остался валидным.
  if ! plutil -lint "$PBXPROJ" >/dev/null 2>&1; then
    echo "export-public: refusing output: project.pbxproj is not a valid plist" >&2
    exit 1
  fi
fi
printf 'Public export created: %s\n' "$OUT"
printf 'Review the export with a secret scanner before publishing.\n'
