<p align="center"><img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — единая панель обходов" width="100%"></p>

<p align="center"><strong>Выберите сервис — RAZVILKA проверит доступные обходы и поможет безопасно применить подходящий маршрут.</strong></p>

<p align="center">
  <a href="README_EN.md">English</a> ·
  <a href="https://github.com/ArtixSx/RAZVILKA/releases">Скачать и обновить</a> ·
  <a href="https://t.me/RAZVILKA_UI">Telegram</a> ·
  <a href="SECURITY.md">Безопасность</a>
</p>

<p align="center">
  <img alt="Keenetic / Netcraze" src="https://img.shields.io/badge/Keenetic%20%2F%20Netcraze-Entware-18a999">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-596a74">
  <img alt="Safe Mode" src="https://img.shields.io/badge/Safe%20Mode-по%20умолчанию-f0b84b">
  <img alt="Local first" src="https://img.shields.io/badge/данные-на%20роутере-43d17b">
</p>

# RAZVILKA

RAZVILKA — бесплатная локальная панель для Keenetic/Netcraze с Entware. Включите Telegram, YouTube, Discord, ChatGPT или собственный ресурс, а панель соберёт его домены и IP-сети, сравнит доступные обходы и подготовит безопасный план применения.

Учётная запись, конфигурации и диагностика находятся на роутере. Облачная регистрация RAZVILKA не требуется.

> Проект ещё проходит аппаратное тестирование. Версия `1.0.0` будет выпущена после проверки разных моделей роутеров, IPv4/IPv6, перезагрузок, low-memory и аварийного восстановления.

## Установка

Нужен роутер с Entware и SSH-доступом `root`. Выполните одну команду:

```sh
curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

Если доступен только `wget`:

```sh
wget -qO- https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh
```

Установщик проверит архитектуру и Entware, сверит SHA-256 релиза, создаст резервную копию и напечатает локальный адрес панели с одноразовым ключом первого входа. После входа задайте собственный логин и пароль.

По умолчанию устанавливается только UI. Нужные обходы добавляются позже из раздела **«Обходы»**, поэтому память роутера не занята неиспользуемыми компонентами.

## Интерфейс

<p align="center">
  <img src="docs/screenshots/overview-v0.15.0.jpg" alt="Обзор RAZVILKA" width="49%">
  <img src="docs/screenshots/services-v0.15.0.jpg" alt="Каталог сервисов RAZVILKA" width="49%">
</p>

## Как пользоваться

1. Откройте **«Обходы»** и установите подходящий компонент.
2. В **«Сервисах»** включите нужный ресурс и оставьте режим `AUTO` либо выберите маршрут вручную.
3. Запустите **«Тест обходов»**, проверьте план и только затем разрешите рабочее применение.

Safe Mode включён после установки: без явного подтверждения панель не меняет firewall, DNS, TUN и policy routing.

## Что поддерживается

| Обход | Для чего нужен |
|---|---|
| **NFQWS2** | DPI-фильтрация, замедление и доменные блокировки без внешнего сервера |
| **WARP · MASQUE** | Полная блокировка по IP через Cloudflare MASQUE, если транспорт доступен |
| **WARP · WireGuard** | Бесплатный split-туннель после подтверждённого handshake |
| **Sing-box** | VLESS/Reality, Hysteria2, TUIC и Shadowsocks через собственный сервер или профиль |
| **Xray** | Альтернативный клиент VLESS/Reality |
| **AmneziaWG** | Туннель к совместимому AmneziaWG-серверу, когда обычный WireGuard распознаётся сетью |

RAZVILKA также предоставляет:

- каталог сервисов и ручное добавление доменов/IP/CIDR;
- отдельные сценарии проверки Telegram, включая Web и Core/API;
- подбор и память подтверждённых стратегий обычного NFQWS2;
- DNS-профили с проверкой доступности и безопасным планом;
- маршруты для отдельных устройств и групп;
- CPU, RAM, Entware, температуру и локальный WAN-трафик;
- экспорт публичных профилей и зашифрованные приватные резервные копии;
- транзакционное применение `plan → snapshot → validate → health → commit/rollback`.

## Рекомендации

- Не публикуйте порт панели в интернет — используйте её только из локальной сети.
- Не отключайте Safe Mode до успешной диагностики и проверки выбранного обхода.
- Для полной IP-блокировки используйте подтверждённый туннель; NFQWS2 предназначен прежде всего для DPI-сценариев.
- Перед обновлением сохраните резервную копию. Повторный запуск установщика сохраняет пользовательские настройки.

## Обновления и поддержка

Описание каждой версии, совместимость и файлы загрузки находятся только в [GitHub Releases](https://github.com/ArtixSx/RAZVILKA/releases).

- Новости и помощь: [@RAZVILKA_UI](https://t.me/RAZVILKA_UI)
- Ошибки и предложения: [GitHub Issues](https://github.com/ArtixSx/RAZVILKA/issues)
- Техническая архитектура: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Лицензия: [MIT](LICENSE)
