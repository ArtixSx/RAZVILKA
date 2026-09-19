<p align="center">
  <img src="docs/assets/razvilka-banner.png" alt="RAZVILKA — управление подключениями на роутере" width="960">
</p>

# RAZVILKA

**Нужные сервисы через подходящее подключение — на вашем роутере.**

Локальная веб-панель для **Keenetic и Netcraze с Entware**. Выбирайте сайты и
устройства, проверяйте доступность, управляйте NFQWS2, WARP и VPN-подключениями
в одном месте. Можно настроить маршрут вручную или разрешить Автопилоту подбирать
проверенный вариант. Панель и расписания работают на роутере, даже когда браузер закрыт.

[Скачать](https://github.com/ArtixSx/RAZVILKA/releases/latest) ·
[Документация](docs/README.md) · [English](README_EN.md) ·
[Новости и поддержка](https://t.me/RAZVILKA_UI)

## Установка

Нужен роутер с установленным **Entware**, подключённым `/opt` и доступом по SSH
в оболочку Entware от `root`. Если Entware ещё нет, начните с
[подготовки роутера](docs/INSTALL_RU.md#подготовка-entware).

| Платформа | Подходящий Entware | Бинарник RAZVILKA |
| --- | --- | --- |
| AArch64 / ARM64 | [aarch64-k3.10](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz) | `arm64` |
| MIPS | [mipssf-k3.4](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz) | `mips`, soft-float |
| MIPSel | [mipselsf-k3.4](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz) | `mipsle`, soft-float |

Выполните **две команды** в SSH. Первая подготавливает HTTPS-загрузку:

```sh
opkg update && opkg install curl ca-certificates ca-bundle
```

Вторая скачивает и запускает установщик:

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh
```

Установщик добавит недостающие базовые утилиты, выберет архитектуру, проверит
контрольные суммы стабильного выпуска и запустит панель.

Откройте **[http://192.168.1.1:8787](http://192.168.1.1:8787)** — либо адрес своего
роутера с портом `8787`. Для первого входа используйте ключ или ссылку настройки,
которые выведет установщик, и задайте логин и пароль. В мастере
«Автопилот» выберите сервисы и устройства или перейдите к ручной настройке.
Нужный обход устанавливается в разделе «Обходы»; VLESS и другие подключения
добавляются в разделе «Подключения». Маршруты включаются после настройки и проверки.

## Обновление

Запустите ту же команду — она установит последний стабильный выпуск,
сохранив настройки и создав снимок для отката:

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh
```

Проверить версию и состояние:

```sh
/opt/bin/razvilka -version
/opt/etc/init.d/S99razvilka status
```

## Удаление

```sh
mkdir -p /opt/tmp && curl -fsSL --retry 2 -o /opt/tmp/razvilka-setup.sh https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh && sh /opt/tmp/razvilka-setup.sh --uninstall
```

Удаляются панель, её автозапуск и собственные активные маршруты. Настройки,
подключения и резервные копии сохраняются для повторной установки.
Entware и отдельно установленные компоненты остаются на месте.
[Утилиты, ручная установка и откат](docs/INSTALL_RU.md).
