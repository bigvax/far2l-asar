# far2l-asar

Нативный бэкенд на языке C для плагина **MultiArc** файлового менеджера **far2l**, обеспечивающий просмотр, извлечение, добавление и замену файлов в архивах **Electron ASAR** (`.asar`).

Представляет собой лёгкий исполняемый ELF-файл со встроенным расчётом SHA-256 (FIPS 180-4) без зависимости от Node.js, npm, OpenSSL или Python при работе в `far2l`.

## Структура проекта

* `src/far2l-asar.c` — исходный код бэкенда на C17.
* `cfg/` — шаблоны секции `[ASAR]` для `custom.ini` (пользовательский и системный).
* `packaging/postinst` — скрипт автоматической настройки `custom.ini` при установке `.deb`-пакета.
* `tests/test_asar.py` — набор интеграционных автотестов.
* `Makefile` — сборка, тестирование, установка, генерация `standalone`-бинарника и `.deb`-пакета.

## Зависимости для сборки

```bash
# Ubuntu / Kubuntu / Debian
sudo apt update && sudo apt install -y build-essential libjansson-dev
```

## Сборка, тестирование и установка

```bash
# Сборка бинарника
make

# Запуск автотестов (требуется Python 3.10+)
make test

# Локальная установка в ~/.local/bin/far2l-asar
# и обновление секции [ASAR] в ~/.config/far2l/plugins/multiarc/custom.ini
make install

# Сборка автономного бинарника (со статически вшитой libjansson) в dist/
make standalone

# Сборка установочного .deb-пакета в dist/
make deb
```

## Управление версией

Текущая версия хранится в файле `VERSION`. Для инкремента предусмотрены цели:
* `make bump-patch` (`1.0.1` → `1.0.2`)
* `make bump-minor` (`1.0.1` → `1.1.0`)
* `make bump-major` (`1.0.1` → `2.0.0`)

## Лицензия

MIT License
