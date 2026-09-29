# Карта изменений, чтобы старый смысл не вернулся

Эта редакция — одно актуальное задание для Claude и Codex. Старые патчи не накладывать.

| Ранее обсуждавшееся положение | Статус V2 | Новое действие |
|---|---|---|
| Default: выбранные сервисы на всём LAN | Заменено последним решением владельца | Default: весь интернет выбранных домашних сегментов, кроме исключений |
| All-internet — только advanced опция | Заменено для новых установок | Advanced/legacy теперь service-only; старые установки без скрытой миграции |
| Выбранные сервисы ограничивают обход | Заменено | Они задают overrides/мониторинг поверх default |
| Удалить сервис = выключить его обход | Уточнено | Снять override → общий путь; DIRECT/блок — отдельные намерения |
| Клиент не входит в scope сервиса → BASE | Требует изменения в новом режиме | Продолжить общие исключения и default |
| Только NFQWS2-маршруты по умолчанию | Не универсальная стартовая схема V2 | NFQWS2 — локальный метод подходящих сервисов; общий coverage определяется capabilities |
| Xray → WG → AWG | Сохранено | Минимальный global contract перед Xray; полный rollout исключений и DNS — gate |
| Сначала весь U1/U2, потом новые движки | Переупорядочено | Только необходимые safety/foundation gaps до Xray |
| Xray TUN описан абстрактно | Уточнено | Топология по installed runtime; existing sidecar first, native TUN только после оценки |
| WARP-WG как обычный WG | Запрещено | Generic WG без регистрации/проверки WARP |
| AWG3.1 как одна универсальная галочка | Уточнено | Tool/module/profile/peer capability, без обещания по одному version label |
| Все неуспехи старого healthcheck ослабляют upgrade proof | Требует исправления/проверки | Typed healthy/degraded/busy/unknown/identity/journal outcomes |
| Успех Retry должен воскресить A | Уточнено | Для C достаточно подтверждённого безопасного состояния, не service PASS мёртвого A |
| 20s ожидания HTTP решает очередь | Только промежуточное | Durable job, bounded preparation, short activation, recheck после ожидания |
| Пауза = Stop | Запрещено | Разные полномочия и последствия |
| Российский список зависит от выбранных сервисов | Запрещено | Классификация определений независима от monitor selection |
| Все .ru включить скрыто через category-ru | Запрещено | Broad TLD/GeoIP — явно отражённые отдельные опции |
| Handshake/port/TUN = весь интернет работает | Запрещено | Runtime, coverage и service evidence раздельны |
| Внешний генератор = обязательный recovery | Запрещено | Локальный lifecycle, внешний output только candidate, permissions отдельно |
| Обновить DNS/export = новая WARP регистрация | Запрещено | Локальное преобразование существующей identity |
| Low-memory = убрать возможности | Не принято владельцем | Chunking, time budgets, concurrency, checkpoint/resume; реальные runtime incompatibilities честно |
| CI/старый HIL = новый physical PASS | Запрещено | Раздельные уровни; все новые кейсы not_run |

## Старые U-этапы и рабочие ветки

| Старая зона | Новые задачи | Примечание |
|---|---|---|
| U0/U1; plan-01-panel | G00, UX01 | Сохранить уже сделанные snapshots, cleanup logout и ясные actions |
| U2; plan-02-queue | G03, F01, R02 | Не создавать вторую очередь; default/service targets и общие бюджеты |
| E1; plan-03-lan | G03, E01, E02 | Новая глобальная семантика, migration и отрицательные проверки |
| D1; plan-04-dns/08-ledger | D01, D02 | General DNS + service override + client exclusions; existing D1 reuse |
| U3; plan-05-recovery | G02, F02, R01 | Safe recovery, default/service independent failure |
| U4; plan-06-catalogs | C01, C02 | Library/candidates не область охвата интернета |
| U5; plan-07-nfqws2 | N01, N02 | Native strategy lifecycle без z2k dependency |
| U6; plan-09-components | X/W/A, M01 | Initial install входит в каждый engine, updates позже |
| U6; plan-10-warp | T01, T02 | Registration ≠ export; H3/H2 и scope |
| U6; plan-11-backends | B01, B02 | Mihomo/HEV без второго controller |
| plan-12-update-trust | G01, M01, M02, L01 | Trust нельзя отложить до auto-update |
| U7; plan-13-auto-update | M02 | Exact release + independent rollback + retention |
| U8; plan-14-acceptance | H01, H02 | Базовые HIL по каждой engine ветке, финальная общая матрица |

От старой карты взять фактические ветки/worktrees и уже принятые изменения. Не создавать новые копии всех 14 веток; actual git history важнее старого номера задания.
