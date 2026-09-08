# ADR: собственная поставка USQUE и нативный адаптер RAZVILKA

Дата: 06.09.2026. Статус: принято для планирования U0–U8; реализация и HIL
не завершены. Основание: раздел 51 пользовательского master-plan редакции 14.

## Решение

Первый кандидат — закреплённый upstream USQUE 4.2.1, собственная проверяемая
сборка и адаптер жизненного цикла RAZVILKA. Полное переписывание MASQUE и смена
языка не требуются без измеренной проблемы. Релиз upstream исправляет
QUIC PROTOCOL_VIOLATION, но не доказывает стабильность на целевом роутере.
[Upstream release](https://github.com/Diniboy1123/usque/releases/tag/v4.2.1).

Исходники, зависимости, встроенные ресурсы, лицензии, SBOM и build
identity фиксируются в manifest. Новый бинарник устанавливается по отдельному
owned-пути; package-owned `/opt/bin/usque` не перезаписывается. Хранятся
active/candidate/previous вместе с совместимой конфигурацией. Нужны проверка
происхождения, completeness всех архитектур и N−1 → N / N → N−1 regression.

WG X25519, MASQUE ECDSA P-256 и доверенный ключ сервера — разные сущности.
`WireGuardCredential`, `MasqueCredential` и `DeviceEnrollment` имеют transport,
generation, provenance и secret refs. Общий account UI не даёт права менять
enrollment рабочего транспорта. Начальная миграция — copy-only импорт,
проверка формата и isolated canary; регистрация — отдельное явное действие.

## Аутентификация и внешнее состояние

Registration HTTPS использует обычную CA/hostname-проверку. MASQUE tunnel
сохраняет обязательный custom verifier server public key, а HTTPS сервиса внутри
туннеля отдельно проверяет собственный сертификат. Не удалять механически
`InsecureSkipVerify`, если это часть обязательной pin-модели; запретить режим
без verifier. Missing/wrong pin, malformed certificate и пустая цепочка должны
давать отказ в H2 и H3.

Новая регистрация ограничена context/timeout/max-body/rate-limit и отправляет
только public key. Timeout после POST может означать созданное удалённое
устройство: нужен исход `remote-created/local-uncommitted` и reconciliation,
а не слепой повтор POST. Локальный file rollback не откатывает Cloudflare.
Приватные ключи не поступают внешним генераторам, в логи или URL.

## Жизненный цикл и приёмка

Adapter владеет process lease, TUN, routes/rules и cleanup. Он различает
installed/configured/running/route-confirmed/service-confirmed, проверяет
конкретный сервис, H2/H3, v4/v6 и UDP capability. Финальное завершение upstream
не вызывает disconnect hook, поэтому cleanup принадлежит RAZVILKA и проверяется
при shutdown/crash/cancel. [Upstream lifecycle](https://github.com/Diniboy1123/usque).

Doctor остаётся read-only. Repair использует отдельное разрешение, cooldown,
ограничение попыток и LKG; зависший туннель не вызывает автоматическую
перерегистрацию. Поздние события старого поколения не меняют новый runtime.

U0–U2: inventory, fixtures, pinned candidate build, bounded API/verifier tests.
U3–U6: native lifecycle, canary, recovery и preview миграции; только один
production owner. U7–U8: измерения RAM/CPU/MTU/throughput, 24–72h soak,
ARM64/MIPS/MIPSel, WAN/reboot и staged rollout. Публикация fork/release и
миграция рабочего роутера — отдельные действия, этим ADR не выполнены.
