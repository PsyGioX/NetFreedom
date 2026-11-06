# Сборка из исходников

Гайд повторяет шаги `.github/workflows/release.yml` (job `windows`) и даёт такой же порядок для Linux:
тесты, release-сборка, сборка пакета из `dist/<платформа>`, контрольные суммы.

Внешних зависимостей у проекта нет, кроме `libc` (Unix) и `windows-sys` (Windows). Они скачиваются
с crates.io; `Cargo.lock` фиксирует версии, поэтому везде используется флаг `--locked`.

Минимальная версия Rust: `Cargo.lock` имеет формат v4, нужен **Rust 1.83 или новее** (проверялось на 1.94.0).

---

## Linux

### 1. Подготовка

```bash
# Rust через rustup (https://rustup.rs) или пакет дистрибутива (нужен >= 1.83)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version

# компоновщик и базовые инструменты (Debian/Ubuntu)
sudo apt install build-essential
```

### 2. Тесты и сборка

```bash
cargo test --locked
cargo build --release --locked
```

Результат: `target/release/netfreedom` (профиль `release`: LTO, `strip`, `panic = "unwind"`).
Бинарник динамически линкуется с glibc; для запуска на других дистрибутивах собирайте на самом старом
из поддерживаемых или добавьте musl-цель (`rustup target add x86_64-unknown-linux-musl`).

### 3. Сборка пакета

```bash
rm -rf package && cp -r dist/linux package
cp target/release/netfreedom package/netfreedom
chmod 755 package/netfreedom
cp LICENSE THIRD-PARTY-NOTICES.md PHILOSOPHY.md README.md package/
rm -f package/SHA256SUMS.txt
```

### 4. Контрольные суммы (формат `хеш␣␣путь`, сортировка по пути)

```bash
cd package
find . -type f ! -name SHA256SUMS.txt | sed 's|^\./||' | LC_ALL=C sort | \
  while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > SHA256SUMS.txt
sha256sum -c --quiet SHA256SUMS.txt && echo OK
cd ..
```

### 5. Архив

```bash
tar -C package -czf NetFreedom-<версия>-linux-x64.tar.gz .
# или: (cd package && zip -qr ../NetFreedom-<версия>-linux-x64.zip .)
```

### 6. Проверка

```bash
./package/netfreedom verify    # сверяет файлы пакета с SHA256SUMS.txt
./package/netfreedom doctor
```

Для запуска (`start`, `tune`) нужны root и `nftables`; движок `nfqws` лежит в `bin/linux-*/`.

### Дополнительно: проверка стратегий

```bash
cargo build --example dump_args
python3 tools/validate_strategies.py     # прогоняет все стратегии через реальный nfqws --dry-run
```

---

## Windows, нативный MSVC

### 1. Подготовка

1. Установите **Visual Studio Build Tools 2022** (или Visual Studio) с компонентом
   **«Разработка классических приложений на C++»** (MSVC v143 и Windows 10/11 SDK).
   В SDK входит `rc.exe`: он нужен, чтобы встроить иконку и сведения о версии в `.exe`.
2. Установите Rust (https://rustup.rs) с хост-целью `x86_64-pc-windows-msvc` (по умолчанию).
3. Откройте **«x64 Native Tools Command Prompt for VS 2022»** или в обычном PowerShell выполните:

```powershell
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
Compress-Archive -Path package/* -DestinationPath "NetFreedom-<версия>-windows-x64.zip" -Force
```

### 4. Проверка

```powershell
.\package\netfreedom.exe verify
.\package\netfreedom.exe doctor
```

Запуск (`start`, `tune`) требует прав администратора; движок `winws` и WinDivert лежат в `bin/`.

### Подпись и релиз

В workflow есть заготовка под подпись кода (SignPath): подписывать `package/netfreedom.exe` нужно
**до** подсчёта контрольных сумм, иначе `verify` не пройдёт. Релиз в CI запускается пушем тега
`v*` (например, `git tag v3.2.0 && git push origin v3.2.0`); тогда же формируется аттестация сборки
(`actions/attest-build-provenance`).

---

## Кросс-сборка Windows-версии на Linux (необязательно)

Это не то, что выпускает CI, но удобно для проверки. Иконка встраивается через `windres`.

```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
cargo build --release --locked --target x86_64-pc-windows-gnu
# результат: target/x86_64-pc-windows-gnu/release/netfreedom.exe
```

Линкер `x86_64-w64-mingw32-gcc` уже указан в `.cargo/config.toml`. Для релиза используйте нативный
MSVC: так собираются официальные пакеты.

---

## Частые проблемы

* `lock file version 4 requires -Znext-lockfile-bump`: слишком старый Rust, обновите до 1.83+.
* `linker 'link.exe' not found` (Windows): не загружено окружение Visual Studio, см. раздел «Подготовка».
* Нет иконки в `.exe`: `rc.exe` не найден в `PATH` во время сборки; пересоберите после загрузки окружения.
* `verify` сообщает о несовпадении: контрольные суммы считались до замены файлов (бинарник, README) или
  до подписи; пересчитайте `SHA256SUMS.txt` как в шаге 4 (Linux) или 3 (Windows).
