# Gap-аудит RAZVILKA на 2026-08-28

> Архивный аудит. Актуальный подтверждённый срез находится в
> [CURRENT_STATUS_RU.md](CURRENT_STATUS_RU.md).

Проверенный срез: ветка `main`, commit `e8cc58ba99774579ad570077ec5c18175c5c80e6`,
последний опубликованный релиз `v0.16.0`. Документ от 25 августа сохранён как
исторический и помечен superseded.

## Итог аудита

RAZVILKA находится на стадии integration hardening. Транзакционное ядро,
Safe Mode, ownership, rollback и несколько реальных dataplane-адаптеров уже
существуют. Поэтому массовая перепись не нужна. Ближайшая работа должна сделать
наблюдения правдивыми, локализовать отказ USQUE, исправить DNS-каталог и только
после этого добавлять repair, live DNS и автоматику.

| Область | Фактическое состояние | Следующий проверяемый рубеж |
|---|---|---|
| Apply и rollback | Рабочая транзакционная база | fault/power-loss матрица на ARM64 и MIPS/MIPSLE |
| Evidence | Линейный уровень и первые canary-факты | outcome, freshness, источник, IPv4/IPv6 и запрет ложного service-confirmed |
| USQUE / WARP MASQUE | Изолированный SOCKS-canary, H3/H2, WARP trace и service proof | Doctor v2 по стадиям; затем только plan-based repair/re-registration |
| WARP WireGuard | Secret-safe import/register и pre-activation canary готовы; ARM64 подтвердил cleanup и блокировку handshake текущим провайдером на UDP 2408/500/1701/4500 | общий Cloudflare Provider, endpoint scan и успешный handshake на другой сети; WARP остаётся best-effort |
| DNS | Schema 4, typed endpoints, безопасный read-only probe, global/service drafts | Resolver Lab v2; live adapter только после rollback gate |
| UI | Service-first интерфейс и отдельные черновики | единые READY/DEGRADED/BLOCKED/UNKNOWN, Lite/Pro и объяснимый путь |
| Release | CI, multi-arch build, checksums и Releases | dev build metadata, prerelease `v0.17.0-rc.1`, hardware artifacts |

## P0 перед следующим prerelease

1. Build provenance: version, commit, build time и известность dirty-state в
   status/UI/diagnostics; tag-сборка обязана сообщать точный tag.
2. DNS catalog correctness: encrypted-only UncensoredDNS, FlashStart только как
   negative control, строгие redirects/TLS/SSRF и честная DNSSEC-семантика.
3. Evidence v2 как backward-compatible слой; route-only, 403/451 и TLS mismatch
   не становятся доказательством работы сервиса.
4. [x] USQUE Doctor v2 остаётся только для чтения и выдаёт явные `SKIPPED` с
   причиной, IPv4/IPv6 отдельно и итог `READY/DEGRADED/BLOCKED/UNKNOWN`.
   Пакет, ядро и конфиг показаны раздельно; окружение не копируется целиком,
   владелец TUN не заявляется без доказательства, а маршрут endpoint через
   собственный TUN считается блокирующей routing loop. Тест фиксирует
   неизменность файлов и разрешает диагностике только read-only команды.
   Права, UID, дата и SHA-256 конфигурации/сессии/бинарника, а также последняя
   известная резервная копия выводятся без содержимого файлов.
5. [x] WARP WireGuard получил отдельный pre-activation canary. На реальном
   ARM64 временный интерфейс, policy rule и таблица удалились после отказа всех
   официальных UDP-портов; live-интерфейс и рабочие маршруты не создавались и
   не менялись. Это фиксирует безопасный отрицательный результат конкретной
   сети, а не обещает доступность WARP у любого провайдера.

## Границы безопасности

- Рабочие NFQWS2, USQUE, transaction, Safe Mode и rollback не переписываются.
- Любая будущая мутация USQUE/DNS имеет plan, ownership, snapshot, validation,
  verification и rollback.
- Чужие route/firewall/DNS/process resources не удаляются.
- `session.conf`, private keys, access tokens и recovery key не возвращаются в
  API, UI, логи или diagnostics.
- TLS verification никогда не отключается; сертификат чужого hostname — жёсткий
  отказ.
- Live DNS, USQUE repair/re-registration и AutoPilot не начинаются до review
  Evidence v2 и read-only Doctor v2.

## Maintainer checklist: история веток и старый PR

- [ ] Создать backup tag перед изменением `dev`.
- [ ] Подтвердить, что деревья `main` и `dev` совпадают, и записать обе SHA.
- [ ] Осознанно пересоздать `dev` от защищённого `main`; не выполнять слепой
      merge или force-push без backup tag.
- [ ] Закрыть устаревший draft PR `#9` с ссылкой на актуальный milestone и
      prerelease.
- [ ] Включить required CI и запрет удаления/force-push `main`.

Эти действия изменяют состояние GitHub и выполняются владельцем отдельно. Они
не являются частью сборки приложения и не запускаются автоматически.
