# Установка RAZVILKA на Keenetic и Netcraze

[Короткая инструкция](../README.md) · [Документация](README.md)

## Подготовка Entware

RAZVILKA устанавливается **поверх готового Entware**. Установщик приложения
не форматирует накопитель, не меняет прошивку и не выбирает раздел диска за вас.

1. Включите поддержку открытых пакетов OPKG в компонентах прошивки.
2. Подготовьте накопитель и установите Entware для архитектуры своей модели.
   Для USB-накопителя используйте поддерживаемую прошивкой файловую систему EXT4.
   Внутреннее хранилище доступно только на поддерживающих его моделях.
3. Убедитесь, что Entware смонтирован в `/opt`, и подключитесь по SSH именно
   к оболочке Entware от `root`. Команды ниже не предназначены для консоли
   настройки прошивки с приглашением `(config)>`.

Подготовка диска и установка Entware описаны в руководствах производителя:
[на USB-накопитель](https://support.netcraze.ru/giga/nc-1012/ru/20980-installing-the-entware-repository-on-a-usb-drive.html),
[во внутреннюю память](https://support.netcraze.ru/ultra/nc-1812/ru/18482-installing-opkg-entware-in-the-router-s-internal-memory.html).
Выбирайте в руководстве свою модель. Форматирование удаляет данные выбранного
раздела, поэтому сначала сохраните нужные файлы.

| CPU / Entware | Официальный установщик Entware | Сборка RAZVILKA |
| --- | --- | --- |
| AArch64, `aarch64-k3.10` | [aarch64-installer.tar.gz](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz) | `razvilka-linux-arm64` |
| MIPS, `mipssf-k3.4` | [mips-installer.tar.gz](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz) | `razvilka-linux-mips` |
| MIPSel, `mipselsf-k3.4` | [mipsel-installer.tar.gz](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz) | `razvilka-linux-mipsle` |

`mips` и `mipsel` различаются порядком байтов. Обе сборки RAZVILKA используют
soft-float. Установщик различает их по ELF-заголовку оболочки, поскольку `uname -m`
может показывать `mips` в обоих случаях. Выбирать бинарник вручную обычно не нужно.
Сборка `amd64` предназначена для разработки и испытаний; это не четвёртый вариант
Entware для перечисленных роутеров. Матрица Entware: [официальная Wiki](https://github.com/Entware/Entware/wiki).

Быстрая проверка готовности:

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
test -d /opt && command -v opkg
uname -m
opkg print-architecture
df -h /opt
```

Если `opkg` не найден, завершите настройку Entware. Если появляется только
приглашение `(config)>`, это другая консоль — подключитесь к SSH-серверу Entware.

## Установка

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
opkg update && opkg install curl wget-ssl ca-certificates ca-bundle
```

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh
```

Скрипт сначала полностью скачивается; он запускается только при успешной загрузке.
Далее установщик проверяет инструменты, получает стабильный архив из GitHub Releases,
сверяет SHA256 и вызывает установщик из этого архива. Само приложение устанавливается
без автоматического запуска всех движков обхода.

После установки откройте `http://<LAN-адрес-роутера>:8787`. Для создания учётной
записи введите ключ первого входа, который вывел установщик, либо перейдите по
выведенной им ссылке настройки. Затем настройте нужные сервисы.
Общего пароля, зашитого в дистрибутив, нет.
При обновлении существующая учётная запись сохраняется.

## Какие утилиты нужны

Наличие перечисленных пакетов проверено 20 сентября 2026 года в официальных
репозиториях [AArch64](https://bin.entware.net/aarch64-k3.10/Packages.html),
[MIPS](https://bin.entware.net/mipssf-k3.4/Packages.html) и
[MIPSel](https://bin.entware.net/mipselsf-k3.4/Packages.html).

| Пакет / инструмент | Зачем нужен |
| --- | --- |
| `curl` | HTTPS-загрузка установщика, выпусков и проверка HTTP |
| `wget-ssl` | Загрузка HTTPS-каталогов через `opkg`, включая NFQWS2 и WARP |
| `ca-certificates`, `ca-bundle` | Проверка сертификатов HTTPS |
| `coreutils-sha256sum` | Сверка контрольных сумм |
| `tar`, `gzip` | Распаковка выпуска и снимки для отката |
| `coreutils-mktemp`, `coreutils-readlink` | Временные каталоги и проверка путей |
| `busybox` | Базовые команды Entware, включая `start-stop-daemon` |
| `ip-full` | Состояние интерфейсов и работа с таблицами маршрутов |
| `iptables` | Правила маршрутизации для поддерживаемых обходов |

Bootstrap сам подготавливает недостающие базовые инструменты. Для ручной
подготовки окружения:

```sh
opkg update && opkg install curl wget-ssl ca-certificates ca-bundle coreutils-sha256sum coreutils-mktemp coreutils-readlink tar gzip busybox ip-full
```

Если нужен обход с правилами iptables и инструмент отсутствует:

```sh
opkg install iptables
```

Не выполняйте `opkg upgrade` всех пакетов ради обновления RAZVILKA. Зависимости
движков и функции ядра проверяются отдельно: установка `iptables` не добавляет
в прошивку отсутствующие модули ядра. `nano`, `htop`, `bash`, Python и компилятор
Go для работы панели не обязательны.

## Обновление

Повторите скачивание и запуск установщика. Получится последний стабильный выпуск,
существующие настройки сохранятся. Установщик печатает путь созданного снимка.

Для конкретной версии скачайте bootstrap без запуска и укажите нужный тег:

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
RAZVILKA_VERSION=v0.18.9 sh /opt/tmp/razvilka-setup.sh
```

Нужен именно опубликованный тег из [Releases](https://github.com/ArtixSx/RAZVILKA/releases).
Старые инструкции кандидатов в `docs/archive` не относятся к текущему выпуску.

## Ручная установка из архива

Скачайте `RAZVILKA-<версия>-entware.tar.gz` и соответствующий файл
`RAZVILKA-<версия>.SHA256SUMS` из одного выпуска. Сверьте SHA256 нужного архива,
распакуйте его и перейдите в распакованный каталог `RAZVILKA-<версия>`.

```sh
sh scripts/upgrade-entware.sh --dry-run
sh scripts/upgrade-entware.sh --apply
```

Запускайте вторую команду после успешной предварительной проверки. Установщик
также проверит `dist/SHA256SUMS`; не удаляйте этот файл из дистрибутива.

## Удаление и откат

**Удаление панели** выполняется отдельно от отката:

```sh
mkdir -p /opt/tmp &&
curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh \
  https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh &&
sh /opt/tmp/razvilka-setup.sh --uninstall
```

Скрипт останавливает панель, убирает её собственные активные маршруты, бинарник
и автозапуск. Каталоги настроек `/opt/etc/razvilka`, состояния
`/opt/var/lib/razvilka` и кэша `/opt/var/cache/razvilka` сохраняются вместе
с подключениями и снимками. Entware и чужие службы не удаляются.

**Откат последнего обновления** возвращает сохранённый снимок:

```sh
sh /opt/tmp/razvilka-setup.sh --rollback
```

Эта команда требует ранее скачанного актуального bootstrap, установленной панели
и доступного снимка. Если панель уже удалена, сначала установите её заново.
Откат может вернуть прежнюю версию панели; это не удаление приложения.
При ручной работе из распакованного выпуска:

```sh
sh scripts/rollback-entware.sh /opt/var/lib/razvilka/update-backups/<снимок>
```

Подставьте путь, который вывел установщик. Не удаляйте вручную весь `/opt`:
там находятся Entware и другие приложения.

## Если панель не открывается

```sh
/opt/etc/init.d/S99razvilka status
/opt/etc/init.d/S99razvilka lan-ip
/opt/bin/razvilka -version
```

Проверьте, что используется LAN-адрес этого роутера и порт `8787`. При ошибке
HTTPS-загрузки проверьте часы роутера и пакеты сертификатов. Если недоступен GitHub,
воспользуйтесь ручной установкой из проверенного архива. Не отключайте проверку TLS
в установочной команде.

## Если каталоги пакетов не обновляются

Сообщение `wget: not an http or ftp url` для адреса `https://` означает, что
`opkg` использует загрузчик без HTTPS. Это возможно после новой установки Entware.
Когда основной каталог Entware уже получен, установите HTTPS-загрузчик и повторите
обновление:

```sh
export PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH
opkg install wget-ssl ca-certificates ca-bundle && opkg update
```

Затем повторите подготовку утилит и установку панели. Если пакет не найден, сначала
проверьте доступность основного каталога Entware. Текущий установщик тоже распознаёт
эту ситуацию: добавляет `wget-ssl` и повторяет загрузку каталогов. В панели нажмите
«Проверить версии»; успешная проверка уберёт отметку об устаревших данных.

## Границы поддержки

Три архитектуры выше остаются обязательными целями сборки проекта. Реальное
испытание на ARM64 и результаты сборок MIPS/MIPSel перечисляются отдельно в
[статусе](CURRENT_STATUS_RU.md). Работоспособность конкретного обхода зависит
от прошивки, движка, профиля и сети провайдера.

OpenWrt пока рассматривается как будущая отдельная платформа. Текущие команды
не устанавливают пакет OpenWrt и не настраивают `procd`, UCI или `firewall4`.
