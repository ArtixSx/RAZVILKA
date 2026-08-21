# Готовность RAZVILKA к массовому релизу

Актуально для `v0.10.0` от 20 августа 2026 года.

## Закрыто программно

- Транзакционный dataplane с неизменяемым SHA-256 планом, атомарными журналами, обратным rollback и boot recovery.
- Активные адаптеры NFQWS2, usque/MASQUE, WARP WireGuard, AmneziaWG, sing-box и Xray с native validation и ownership.
- Endpoint/self-loop guards, отдельные policy tables/priorities, IPv4/IPv6 rules и безопасное обновление DNS-разрешённых адресов.
- Service-first AUTO с подтверждёнными изолированными тестами, hysteresis, cooldown, failover и объяснением выбора.
- Локальные устройства, имена/группы и source-scoped tunnel policy; NFQWS2 честно блокирует неподтверждаемую per-device область.
- Conntrack-телеметрия только при подтверждении фактического kernel route; без фиктивных соединений и без облачной истории.
- 16 встроенных сервисов, 35 allowlisted community manifests, custom-сервисы, provenance, лимиты, overlap preview и SSRF-защита.
- Guided/expert конфиги всех обходов, публичный secret-free профиль и отдельный AES-256-GCM приватный backup с draft-only restore.
- Локальная регистрация, recovery URL/key, парольные сессии, throttling, Origin/JSON gates и отзыв сеансов без переиспользования SSH-пароля.
- Установка одной командой, автоматическая установка доступных обходов, component version/update UI, snapshot upgrade/rollback/uninstall.
- Privacy-safe диагностический отчёт, ручное уведомление об официальном релизе и GitHub/Sigstore attestation release-артефактов.

## Осознанные ограничения `v0.10.0`

- Один сервис имеет один выбранный маршрут. Его область может включать несколько IP/подсетей устройств, но разные маршруты одного сервиса для двух групп потребуют schema v2 с приоритетами правил.
- NFQWS2 применяется через штатный `nfqws2-keenetic` init и RAZVILKA-managed блоки списков. Персональная привязка устройств остаётся функцией политики Keenetic/NFQWS2 и не объявляется доказанной RAZVILKA.
- IP-адреса CDN могут пересекаться у разных сервисов. Неоднозначное совпадение пропускается в Connections, а не угадывается.
- ECH, QUIC и быстро меняющиеся CDN означают, что одних статических доменных списков недостаточно; policy refresh и повторные service probes обязательны.
- `usque-keenetic` устанавливается через закреплённый opkg feed и не перезаписывается внешним asset; upstream checksum внешнего `wgcf` подтверждает целостность относительно его релиза, но не заменяет подпись автора. Bundle самой RAZVILKA покрывается artifact attestation.
- UI намеренно не исполняет обновление менеджера от имени root: он показывает проверенную версию и копируемую транзакционную команду.

## Единственный блокер `1.0.0`: hardware release gate

Программный release candidate не равен массовому релизу. Перед тегом `1.0.0` нужно зафиксировать успешные результаты минимум на ARM64 и одном MIPS/MIPSLE устройстве:

1. Чистая установка и обновление поверх предыдущей версии с восстановлением всех пользовательских данных.
2. NFQWS2, один WARP-маршрут и один proxy-маршрут отдельно и одновременно.
3. IPv4/IPv6, PPPoE/обычный WAN, TUN, NFQUEUE и включённый/выключенный hardware offload.
4. Обрыв питания/kill процесса на каждой фазе Apply, неуспешный health, reboot и boot-loop guard.
5. Low-memory/OOM и длительный soak с крупным каталогом/conntrack без потери интернета у direct-трафика.
6. Конфликт существующих TUN, портов, policy priorities, AdGuard/DNS и стороннего NFQWS2.
7. Rollback и uninstall удаляют только RAZVILKA-owned объекты и возвращают предыдущий сервис.
8. LAN security review: brute force, session revoke, Origin, permissions секретов, backup и диагностический отчёт.

До прохождения этой матрицы корректное имя версии — `0.9.x release candidate`. Малые исправления получают `0.9.1`, крупная переработка форматов — новый minor; `1.0.0` не назначается по одному успешному запуску.
