# Источники, текущая база и ограничения проверки

Дата подготовки: 2026-09-29. Новые документы — план; проверки программы в этой поставке не запускались.

## Что использовано

| ID | Источник | Что подтверждает / ограничение |
|---|---|---|
| S1 | Последнее уточнение владельца в этом чате | Весь интернет всех согласованных домашних клиентов, исключения и выбранные сервисы как overrides; Xray→WG→AWG |
| S2 | `RAZVILKA_UNIFIED_MASTER_PLAN_R19_2026-09-08.md`, сохранённый Library-файл; разделы 55–56 и поиск требований | Полная автоматизация, один scheduler, разрешения без повторных модалок, AI-группа с независимыми service policies; исторический service-first default заменён S1 |
| S3 | Приложенный `RAZVILKA_0.18.14_отчёт.txt`, Claude, 28–29.09.2026 | Документированные ревью/HIL/оптимизации, incident NFQWS2 update, manual recovery, ограничения; не новый независимый замер |
| S4 | `docs/CURRENT_STATUS_RU.md` на `46ba8761` | Установка 0.18.15 на AArch64, маршруты не подтверждены; очередь/DNS частично; открытые LAN/updates/soak |
| S5 | `docs/plans/unified-lan-2026-09-22/EXECUTION_RU.md`, прочитанный в предыдущей проверке | Исторические точные результаты выпуска, не текущая аппаратная проверка |
| S6 | `docs/ROADMAP.md`, `docs/BRANCHES_RU.md` на том же HEAD, ранее прочитанные в этом чате | Старые U1–U8 и 14 веток; порядок/defaults теперь нужно согласовать с S1 |
| S7 | Предыдущие аудиты 0.18.14/0.18.15 в чате и сохранённые review-пакеты | Замечания к installer/journal; в этой поставке стенды не перезапускались. Сначала воспроизвести на actual checkout |
| S8 | Повторно прочитан `internal/config/network_policy.go`, строки 1–240 на `46ba8761` | `lan_except/all_except`, конкретный список DefaultRoute, retain/base, typed site rules и RU model; intent не runtime |
| S9 | Повторно прочитан `internal/autonomy/network_policy.go`, строки 1–335 | Чистая решающая функция, ранний BASE при service-scope mismatch, финальный all_except bypass, conflict model; не packet proof |
| S10 | Повторно прочитан `scripts/upgrade-entware.sh`, строки 270–330 | Широкое отрицание strict prior check ослабляет конечный режим; нового полного installer run не было |
| S11 | Официальный Project X, Routing, прочитан 29.09 | Порядок rules, unmatched first outbound, domain identity; не проверка installed Xray версии |
| S12 | Официальный sing-box, TUN, прочитан 29.09 | Версионные auto_route/redirect/DNS/strict_route особенности; не рецепт поставить latest на Keenetic |
| S13 | Официальный WireGuard: overview/cryptokey routing и quickstart | AllowedIPs, keys, WG lifecycle, keepalive; не доказательство работоспособности конкретного peer |
| S14 | Официальная AmneziaWG documentation, прочитана 29.09 | Параметры/совместимость: сверять actual tool/module/peer |
| S15 | Полностью прочитан сохранённый `RAZVILKA_CLAUDE_PLAN_RU.md` от 29.09, 533 строки | Главная опорная версия, 26 разделов; конфликтующий service-only default заменён |
| S16 | Прочитан сохранённый `MASTER_PLAN_RU.md` из Codex handoff 28.09, 512 строк | Сохранена очередь engines, внешние идеи, LAN/DNS/NFQ/WARP/updates |
| S17 | GitHub branches/main, заново получен 29.09 | HEAD 46ba8761, родитель 450496ed (0.18.15) |

## Адреса для Claude / Codex

- Repo: https://github.com/ArtixSx/RAZVILKA
- Snapshot: https://github.com/ArtixSx/RAZVILKA/tree/46ba8761cc0a374ddfbbf82adf6253762c3a0040
- Status: https://github.com/ArtixSx/RAZVILKA/blob/46ba8761cc0a374ddfbbf82adf6253762c3a0040/docs/CURRENT_STATUS_RU.md
- Policy: https://github.com/ArtixSx/RAZVILKA/blob/46ba8761cc0a374ddfbbf82adf6253762c3a0040/internal/config/network_policy.go
- Decision: https://github.com/ArtixSx/RAZVILKA/blob/46ba8761cc0a374ddfbbf82adf6253762c3a0040/internal/autonomy/network_policy.go
- Installer: https://github.com/ArtixSx/RAZVILKA/blob/46ba8761cc0a374ddfbbf82adf6253762c3a0040/scripts/upgrade-entware.sh
- Project X: https://xtls.github.io/en/config/routing.html
- sing-box: https://sing-box.sagernet.org/configuration/inbound/tun/
- WireGuard: https://www.wireguard.com/ and https://www.wireguard.com/quickstart/
- AmneziaWG: https://docs.amnezia.org/documentation/amnezia-wg/

## Граница проверки

В этой сессии не выполнены: полный checkout-аудит, go test/check.sh/race/vet проекта, native engine runs, release artifact attestation, SSH, реальная LAN, создание WARP registration, API генераторов, новая проверка всех перечисленных внешних репозиториев, HIL/soak. Сайт https://warp-gen.cyb-portal.org/ при текущем обращении не дал доступного содержимого; это ограничение чтения, не доказательство его общей недоступности.

Ни одна рекомендация из форума/README и ни один старый тест не становятся автоматически runtime capability. При реализации фиксировать новый source commit/date/license и свой тест. Результаты в приложенной матрице намеренно `not_run`.
