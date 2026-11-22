# Сборка из исходников

Гайд повторяет шаги `.github/workflows/release.yml` (jobs `build` и `package`) и даёт тот же порядок для Linux:
тесты, release-сборка, сборка пакета из `dist/<платформа>`, контрольные суммы, архив, проверка.

**Содержание**

1. [Что понадобится](#что-понадобится)
2. [Получение исходников](#получение-исходников)
3. [Linux](#linux)
4. [Windows, нативный MSVC](#windows-нативный-msvc)
5. [Кросс-сборка Windows-версии на Linux](#кросс-сборка-windows-версии-на-linux-необязательно)
6. [Подпись и релиз](#подпись-и-релиз)
7. [Частые проблемы](#частые-проблемы)

---

## Что понадобится

| | Linux | Windows |
|---|---|---|
| Rust | **1.83 или новее** (проверялось на 1.94.0) | **1.83 или новее**, цель `x86_64-pc-windows-msvc` |
| Компоновщик | `gcc`/`cc` (пакет `build-essential`) | MSVC v143 + Windows 10/11 SDK |
| Внешние зависимости крейтов | `libc` | `windows-sys` |
| Нужно при запуске | root, `nftables` | права администратора, драйвер WinDivert из `bin/` |
| Интернет при сборке | да, для crates.io (один раз) | да, для crates.io (один раз) |
| Свободное место | около 1 ГБ (инструментарий + `target/`) | около 8 ГБ (Build Tools + Rust + `target/`) |

Других внешних зависимостей у проекта нет. Крейты скачиваются с crates.io; `Cargo.lock` фиксирует версии,
поэтому везде используется флаг `--locked`: он гарантирует, что соберутся ровно те версии, что проверены.

Минимальная версия Rust: `Cargo.lock` имеет формат v4, нужен **Rust 1.83 или новее**.

---

## Получение исходников

```bash
git clone https://github.com/PsyGioX/NetFreedom.git
cd NetFreedom
```

Для сборки конкретного релиза переключитесь на его тег:

```bash
git checkout v4.7.0
```

Все команды ниже выполняются из корня репозитория.

---

## Linux

Команды проверены на Debian/Ubuntu. Для Fedora, Arch и других дистрибутивов отличается только установка пакетов.

### 1. Подготовка

Установите Rust через rustup (рекомендуется, версия всегда свежая) или пакетом дистрибутива (нужен >= 1.83):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version     # должно быть 1.83.0 или выше
cargo --version
```

Компоновщик и базовые инструменты:

```bash
# Debian / Ubuntu
sudo apt install build-essential curl git nftables

# Fedora
sudo dnf install gcc make curl git nftables

# Arch
sudo pacman -S base-devel curl git nftables
```

`nftables` нужен только для запуска (`start`, `tune`), для самой сборки он не требуется. Пакеты
`zip` (для `.zip`-архива) и `python3` (для проверки стратегий) ставьте по необходимости.

Если Rust из пакета дистрибутива старше 1.83, обновите его через rustup:

```bash
rustup update stable
```

### 2. Тесты и сборка

```bash
cargo test --locked
cargo build --release --locked
```

Результат: `target/release/netfreedom` (профиль `release`: LTO, `strip`, `panic = "unwind"`).
Первая сборка занимает заметно дольше последующих: скачиваются и компилируются зависимости.

Бинарник динамически линкуется с glibc. Для запуска на других дистрибутивах есть два пути:

* собирать на самом старом из поддерживаемых дистрибутивов (glibc обратно совместима, но не наоборот);
* собрать статический бинарник с musl:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
cargo build --release --locked --target x86_64-unknown-linux-musl
# результат: target/x86_64-unknown-linux-musl/release/netfreedom
```

Проверить, что получилось:

```bash
file target/release/netfreedom
ldd target/release/netfreedom     # для musl-сборки: «not a dynamic executable»
```

### 3. Сборка пакета

В `dist/<платформа>` лежат только сторонние и исходные компоненты (`bin/`, `lists/`, `utils/`, лицензии).
Бинарник `netfreedom`, `README.md` и `SHA256SUMS.txt` в репозитории не хранятся: они создаются при сборке
(так не бывает устаревшего бинарника рядом со свежими списками).

```bash
rm -rf package && cp -r dist/linux package
cp target/release/netfreedom package/netfreedom
chmod 755 package/netfreedom
cp LICENSE THIRD-PARTY-NOTICES.md PHILOSOPHY.md README.md package/
rm -f package/SHA256SUMS.txt
```

Для musl-сборки замените источник бинарника на `target/x86_64-unknown-linux-musl/release/netfreedom`.

### 4. Контрольные суммы (формат `хеш␣␣путь`, сортировка по пути)

```bash
cd package
find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | \
  while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > SHA256SUMS.txt
sha256sum -c --quiet SHA256SUMS.txt && echo OK
cd ..
```

`OK` в конце означает, что все файлы пакета совпали со списком. Контрольные суммы считаются **после**
того, как в `package/` лежат все финальные файлы: любое изменение позже требует пересчёта.

### 5. Архив

Подставьте номер версии вместо `<версия>` (например, `4.7.0`):

```bash
tar -C package -czf NetFreedom-<версия>-linux-x64.tar.gz .
# или: (cd package && zip -qr ../NetFreedom-<версия>-linux-x64.zip .)
```

Контрольная сумма самого архива (для страницы релиза):

```bash
sha256sum NetFreedom-<версия>-linux-x64.tar.gz
```

### 6. Проверка

```bash
./package/netfreedom verify    # сверяет файлы пакета с SHA256SUMS.txt
./package/netfreedom doctor    # проверяет окружение (права, nftables, движок)
```

Для запуска (`start`, `tune`) нужны root и `nftables`; движок `nfqws` лежит в `bin/linux-*/`.

```bash
sudo ./package/netfreedom start
```

### Дополнительно: проверка стратегий

```bash
cargo build --example dump_args
python3 tools/validate_strategies.py     # прогоняет все стратегии через реальный nfqws --dry-run
```

Запускайте после любого изменения стратегий: скрипт ловит опечатки в аргументах до релиза.

### Сборка одной командой (Linux)

Если нужно воспроизвести все шаги подряд:

```bash
set -euo pipefail
VERSION=4.7.0                       # укажите нужную версию

cargo test --locked
cargo build --release --locked

rm -rf package && cp -r dist/linux package
cp target/release/netfreedom package/netfreedom
chmod 755 package/netfreedom
cp LICENSE THIRD-PARTY-NOTICES.md PHILOSOPHY.md README.md package/
rm -f package/SHA256SUMS.txt

( cd package
  find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | \
    while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > SHA256SUMS.txt
  sha256sum -c --quiet SHA256SUMS.txt && echo OK )

tar -C package -czf "NetFreedom-${VERSION}-linux-x64.tar.gz" .
./package/netfreedom verify
```

---

## Windows, нативный MSVC

Все команды выполняются в **PowerShell** (5.1 или 7+).

### 1. Подготовка

**Вариант А: через winget (быстро)**

```powershell
winget install --id Rustlang.Rustup -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Git.Git -e
```

После установки закройте и заново откройте PowerShell, чтобы обновился `PATH`.

**Вариант Б: вручную**

1. Установите **Visual Studio Build Tools 2022** (или Visual Studio) с компонентом
   **«Разработка классических приложений на C++»** (MSVC v143 и Windows 10/11 SDK).
   В SDK входит `rc.exe`: он нужен, чтобы встроить иконку и сведения о версии в `.exe`.
2. Установите Rust (https://rustup.rs) с хост-целью `x86_64-pc-windows-msvc` (по умолчанию).

**Проверка и загрузка окружения Visual Studio**

Откройте **«x64 Native Tools Command Prompt for VS 2022»** или в обычном PowerShell выполните:

```powershell
rustc --version      # 1.83.0 или выше
rustup show          # активная цель должна быть x86_64-pc-windows-msvc

& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
# затем загрузите окружение, подставив найденный путь:
& "<путь>\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -SkipAutomaticLocation
where.exe rc
```

Если `where.exe rc` ничего не нашёл, сборка пройдёт, но у `netfreedom.exe` будет иконка по умолчанию
(в CI это решает шаг `ilammy/msvc-dev-cmd@v1`).

Статическая CRT включена в `.cargo/config.toml` (`+crt-static`), поэтому Visual C++ Redistributable
на машине пользователя не нужен.

### 2. Тесты и сборка (как в workflow)

```powershell
cargo test --locked
cargo build --release --locked
```

Результат: `target\release\netfreedom.exe`.

### 3. Сборка пакета и контрольные суммы (шаг `Assemble the package`)

```powershell
Remove-Item -Recurse -Force package -ErrorAction SilentlyContinue
Copy-Item -Recurse dist/windows package
Copy-Item target/release/netfreedom.exe package/netfreedom.exe
Copy-Item LICENSE, THIRD-PARTY-NOTICES.md, PHILOSOPHY.md, README.md package/
Remove-Item package/SHA256SUMS.txt -ErrorAction SilentlyContinue
Push-Location package
Get-ChildItem -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
  $rel = (Resolve-Path -Relative $_.FullName).Substring(2) -replace '\\','/'
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
} | Sort-Object { $_.Substring(66) } | Set-Content -Encoding ascii SHA256SUMS.txt
Pop-Location
```

Подпись кода (если используется) выполняется **до** этого шага, см. [«Подпись и релиз»](#подпись-и-релиз).

### 4. Архив

Подставьте номер версии вместо `<версия>`:

```powershell
Compress-Archive -Path package/* -DestinationPath "NetFreedom-<версия>-windows-x64.zip" -Force
Get-FileHash "NetFreedom-<версия>-windows-x64.zip" -Algorithm SHA256
```

### 5. Проверка

```powershell
.\package\netfreedom.exe verify    # сверяет файлы пакета с SHA256SUMS.txt
.\package\netfreedom.exe doctor    # проверяет окружение (права, драйвер)
```

Запуск (`start`, `tune`) требует прав администратора (PowerShell «от имени администратора»).
Драйвер WinDivert (`WinDivert.dll`, `WinDivert64.sys`) лежит в `bin/`; сам движок встроен в `netfreedom.exe`.
Не переносите `netfreedom.exe` отдельно от папки `bin/`: драйвер ищется рядом с ним.

Если Windows Defender или SmartScreen реагирует на неподписанный `netfreedom.exe`, это ожидаемо для
сборки без подписи кода: драйвер перехвата пакетов (WinDivert) часто вызывает предупреждения у антивирусов.
Сверяйте хеши из `SHA256SUMS.txt` и релиза, чтобы убедиться, что файлы не изменены.

### Сборка одной командой (Windows)

```powershell
$ErrorActionPreference = 'Stop'
$Version = '4.7.0'                  # укажите нужную версию

cargo test --locked
cargo build --release --locked

Remove-Item -Recurse -Force package -ErrorAction SilentlyContinue
Copy-Item -Recurse dist/windows package
Copy-Item target/release/netfreedom.exe package/netfreedom.exe
Copy-Item LICENSE, THIRD-PARTY-NOTICES.md, PHILOSOPHY.md, README.md package/
Remove-Item package/SHA256SUMS.txt -ErrorAction SilentlyContinue

Push-Location package
Get-ChildItem -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
  $rel = (Resolve-Path -Relative $_.FullName).Substring(2) -replace '\\','/'
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
} | Sort-Object { $_.Substring(66) } | Set-Content -Encoding ascii SHA256SUMS.txt
Pop-Location

Compress-Archive -Path package/* -DestinationPath "NetFreedom-$Version-windows-x64.zip" -Force
.\package\netfreedom.exe verify
```

---

## Кросс-сборка Windows-версии на Linux (необязательно)

Это не то, что выпускает CI, но удобно для быстрой проверки. Иконка встраивается через `windres`.

```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo build --release --locked --target x86_64-pc-windows-gnu
# результат: target/x86_64-pc-windows-gnu/release/netfreedom.exe
```

Линкер `x86_64-w64-mingw32-gcc` уже указан в `.cargo/config.toml`. Для релиза используйте нативный
MSVC: так собираются официальные пакеты. Результат кросс-сборки запускать нужно на Windows;
сборка пакета выполняется так же, как в разделе Windows, но с этим `.exe`.

---

## Подпись и релиз

В workflow есть заготовка под подпись кода (SignPath): подписывать `package/netfreedom.exe` нужно
**до** подсчёта контрольных сумм, иначе `verify` не пройдёт.

Релиз в CI запускается пушем тега `v*`:

```bash
git tag v4.7.0
git push origin v4.7.0
```

Тогда же формируется аттестация сборки (`actions/attest-build-provenance`). Версия в теге должна
совпадать с версией в `Cargo.toml`.

Чек-лист перед тегом:

1. `cargo test --locked` проходит на Linux и Windows.
2. `python3 tools/validate_strategies.py` проходит без ошибок.
3. Версия в `Cargo.toml` обновлена, `Cargo.lock` закоммичен.
4. `netfreedom verify` на собранных пакетах сообщает об успехе.

---

## Частые проблемы

* `lock file version 4 requires -Znext-lockfile-bump`: слишком старый Rust, обновите до 1.83+ (`rustup update stable`).
* `linker 'cc' not found` (Linux): не установлены инструменты сборки, выполните `sudo apt install build-essential`.
* `linker 'link.exe' not found` (Windows): не загружено окружение Visual Studio или не установлен компонент C++, см. раздел «Подготовка».
* `error: failed to run custom build command` / ошибки `rc.exe`: проверьте, что Windows SDK установлен и `where.exe rc` находит `rc.exe`.
* Нет иконки в `.exe`: `rc.exe` не найден в `PATH` во время сборки; загрузите окружение и пересоберите (`cargo clean -p netfreedom`, затем `cargo build --release --locked`).
* `failed to get ... from crates.io` / обрыв загрузки: проблема сети или блокировка; повторите сборку, при необходимости настройте прокси или зеркало в `~/.cargo/config.toml`.
* `verify` сообщает о несовпадении: контрольные суммы считались до замены файлов (бинарник, README) или
  до подписи; пересчитайте `SHA256SUMS.txt` как в шаге 4 (Linux) или 3 (Windows).
* `Permission denied` при запуске на Linux: нет бита исполнения; выполните `chmod 755 package/netfreedom`.
* `start` или `tune` сразу завершается с ошибкой доступа: запустите с правами root (Linux) или от имени администратора (Windows).
