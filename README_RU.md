<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — единая панель маршрутизации" width="100%">
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="https://t.me/RAZVILKA_UI">Telegram</a> ·
  <a href="CHANGELOG.md">История версий</a> ·
  <a href="SECURITY.md">Безопасность</a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-0.12.0-46d77b">
  <img alt="Keenetic / Netcraze" src="https://img.shields.io/badge/Keenetic%20%2F%20Netcraze-Entware-18a999">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-596a74">
  <img alt="Safe Mode" src="https://img.shields.io/badge/Safe%20Mode-default-f0b84b">
</p>

# RAZVILKA

RAZVILKA — бесплатная локальная панель для Keenetic/Netcraze. Пользователь выбирает нужные сайты и приложения, а панель устанавливает доступные обходы, проверяет их и назначает каждому сервису рабочий маршрут.

Внешний аккаунт и облачный сервер не нужны: интерфейс, конфигурация и диагностические данные находятся на самом роутере.

> **v0.12.0 — публичная preview-версия.** Установка и обновление проверены на Netcraze Ultra NC-1812 (ARM64, KeeneticOS 5.1.3). Версия `1.0.0` будет выпущена после расширенных reboot/fault/IPv6/low-memory и multi-model тестов.

## Что умеет

- включает YouTube, Discord, Telegram, ChatGPT, Spotify и другие сервисы одним переключателем;
- устанавливает только выбранные обходы — UI не перегружает роутер ненужными компонентами;
- управляет NFQWS2, WARP/MASQUE, WARP/WireGuard, sing-box, Xray и AmneziaWG из одной панели;
- сравнивает маршруты изолированными проверками и использует подтверждённые результаты для `AUTO`;
- подбирает и проверяет стратегии обычного NFQWS2 в Strategy Lab — отдельный z2k-сервис не устанавливается;
- показывает CPU, RAM, Entware, WAN-трафик и запас ресурсов роутера;
- добавляет пользовательские сервисы, домены/CIDR и проверяемые источники списков;
- экспортирует публичные профили и зашифрованные приватные backup-конфигурации;
- применяет изменения через `plan → snapshot → validate → health → commit/rollback`.

## Установка одной командой

Нужно заранее включить Entware на накопителе и войти в роутер по SSH под `root`.

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

Если в Entware есть только `wget`:

```sh
wget -qO- https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

Установщик проверит Entware и архитектуру, скачает stable release, сверит SHA-256, создаст rollback-снимок, запустит RAZVILKA и покажет адрес панели.

По умолчанию ставится только UI. Обходы затем устанавливаются по одному во вкладке **«Обходы»**. Для автоматической установки доступного starter pack используйте:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh -s -- --starter-pack
```

Поддерживаемые архитектуры: `arm64`, `mips`, `mipsle`, `amd64`.

## Первый вход

После чистой установки консоль покажет:

```text
[OK] RAZVILKA 0.12.0 установлена и запущена
Панель: http://192.168.1.1:8787
Ключ настройки: <уникальный recovery key>
```

Откройте выведенную ссылку и создайте собственный логин и пароль. Универсального пароля `admin/admin` нет: он сделал бы все установки одинаково уязвимыми. SSH-пароль роутера панели не передаётся.

При обновлении существующая учётная запись сохраняется, а recovery key повторно в консоль не печатается.

## Настройка без командной строки

1. Откройте **«Обходы»** и установите NFQWS2 либо другой нужный компонент.
2. В **«Сервисах»** включите нужные ресурсы и оставьте маршрут `AUTO` или выберите его вручную.
3. Запустите **«Тест обходов»**, проверьте план и только затем отключите Safe Mode для Active Apply.

Safe Mode включён при первой установке и не меняет firewall, DNS, TUN или policy routing до явного подтверждения.

## Интерфейс

### Обзор сервисов, маршрутов и ресурсов

![Обзор RAZVILKA v0.12.0](docs/screenshots/overview-v0.12.0.png)

### Понятный результат сравнения обходов

Вместо JSON панель показывает итог, статус каждого маршрута и причину решения. Полный API-ответ остаётся под сворачиваемой кнопкой «Показать технические данные».

![Тест обходов RAZVILKA v0.12.0](docs/screenshots/route-test-v0.12.0.png)

### Мастер первого запуска

![Мастер настройки RAZVILKA v0.12.0](docs/screenshots/onboarding-v0.12.0.png)

## Обходы

| Компонент | Назначение | Установка |
|---|---|---|
| NFQWS2 | локальный DPI-desync / Zapret2 | из UI или starter pack |
| WARP · MASQUE | Cloudflare WARP через usque | из UI при наличии совместимого пакета |
| WARP · WireGuard | WARP-профиль и policy route | из UI |
| WARP Generator | создание, проверка, импорт и замена профиля | из UI |
| sing-box / Xray | VLESS, Reality, Hysteria2, TUIC, Shadowsocks | из UI, профиль пользователя |
| AmneziaWG | WireGuard-совместимый DPI-resistant туннель | только при совместимом ядре/репозитории |

Доступность пакета зависит от архитектуры, версии KeeneticOS и подключённых opkg-репозиториев. RAZVILKA не изображает отсутствующий компонент работающим и не включает маршрут без health evidence.

## Обновление и восстановление

Повторите команду установки — конфиги, пользовательские сервисы, учётная запись и рабочий dataplane будут сохранены:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

Установщик записывает путь последнего снимка в `/opt/var/lib/razvilka/current-backup` и автоматически возвращает его, если новая версия не проходит health-check. Для ручного восстановления используйте `scripts/rollback-entware.sh` из release bundle той же версии.

## Проверка проекта

```sh
./scripts/check.sh
```

Проверка запускает Go tests, race detector, vet, JavaScript/shell syntax, кросс-сборки `amd64/arm64/mips/mipsle`, сверку SHA-256 и тест транзакционного Entware apply/rollback.

Архитектура и ограничения подробно описаны в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), план до `1.0.0` — в [docs/ROADMAP.md](docs/ROADMAP.md).

## Поддержка

- Telegram: [@RAZVILKA_UI](https://t.me/RAZVILKA_UI)
- Ошибки и предложения: [GitHub Issues](https://github.com/ArtixSx/RAZVILKA/issues)
- Уязвимости: [SECURITY.md](SECURITY.md)

RAZVILKA распространяется бесплатно по лицензии [MIT](LICENSE).
