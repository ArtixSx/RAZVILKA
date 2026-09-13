> **Архив исходного импорта.** Ниже сохранён отчёт и технический план исходного этапа, а не текущий статус проекта. Прежние команды, слова «не собран» и «следующий шаг» относятся к тому срезу; это не инструкция повторно выполнить старую очередь. Актуальные исправления и подтверждения: [DC1 review](DC1_REVIEW_2026-09-13_RU.md) и [текущий статус](CURRENT_STATUS_RU.md).

# Продолжение DC1 для Codex

## Источник и первая команда

Взять **полный DC1 SOURCE.zip или DC1.git.bundle**, не standalone HTML, не архив только frontend и не малый остановленный R5 delivery. База — `64af021bbc5f367f8968a6e56b925df7f700d00f` AWG31-WARP. Все изменения DC1 отдельным локальным commit; remote main не менялся.

Сначала AGENTS.md, если имеется, `git status`, `git log -1`, `CANDIDATE_DC1_RU.md`, `docs/DNS_COMMUNITY_UNIFIED_DC1_RU.md`, прежний `CODEX_AWG31_WARP_RU.md` из полного baseline в части открытых задач. Не исполнять заново старый roadmap о создании NodeStore.

## P0: полная проверка новой интеграции

```sh
# Требуется настоящий Go 1.26.5. Не снижать go.mod/go.sum.
go version
go mod verify
go test -count=1 ./internal/dnscontrol ./internal/app ./internal/recipehints
go test -race -count=1 ./...
go vet ./...
node scripts/build-interface.mjs --check
for f in scripts/test-*.mjs; do node "$f" || exit 1; done
# Прочитать этот script: он делает сборку/изолированный rehearsal, не запускать на live router.
sh scripts/check.sh
```

В исходном окружении новая dnscontrol/app интеграция НЕ компилировалась: загрузка toolchain завершилась DNS/network error. Только recipehints протестирован отдельно на Go1.23.2 в отключённом module-режиме, поскольку пакет stdlib-only. Не объявлять это полным Go gate.

Проверить новые `internal/dnscontrol/service_compare_test.go`, `internal/app/dns_service_compare_test.go`. HTTP guards используют существующий fixture; тесты до внешней сети. Дополни настоящим `httptest.Server` + injectable DNS transport, CSRF/session и cancelled HTTP context. Прямой action auth содержит no-store и revision fence. Для service policy без direct fallback системный DNS probe намеренно отказан.

Новый route `/api/v1/dns/service-compare` интегрирован в app.go, existing operationMiddleware и исключение из gratuitous interruptAutomation. Нужен тест, что он не отменяет healthy Auto и не блокирует emergency cancel. Сейчас запрос синхронный, держит exclusive admission до32сек; не включать его массово в scheduler до job/lease/fairness доработки.

Рассмотреть ошибки ответа: invalid input400, unavailable503, stale409, cancel/deadline — typed code; сейчас last two возвращаются400 через общий error. Это ограничение текущего UI-прототипа API, не окончательная taxonomy. Никаких raw external TLS/DNS error strings с секретами.

## Реально изменённые точки

- `internal/dnscontrol/provider_metadata.go`, additions in `dnscontrol.go`: typed role/trust/hints. Малw/Comss encrypted templates; GeoHide/Redirect not configured. Схема document остаётся4; поля Provider additive. Проверить migrations/custom snapshot roundtrip.
- `internal/dnscontrol/service_compare.go`: общий строгий DNS exchange, только A/AAAA и address set fingerprint. Нет TTL/CNAME output, SNI/service checks, net-generation/factual request route proof, записи memory/winner или Apply.
- `internal/app/dns_service_compare.go`: request DTO, не принимает URL пользователя напрямую, выбирает существующий HTTPS probe hostname; no remote account action.
- `cmd/razvilka/web/dns-service-lab.js`: реальный API consumer; mode result-only, no localStorage/polling. После logout clear/abort. Стили в существующем `interface-shell.css`, compiled `interface.css`, общийcachekey dc1.
- `internal/recipehints/*`: pure model, hash, signed catalogue verification and shortlist. **Пакет ещё ниоткуда в app не вызывается.** Нет ingest, network fetch, client consent writer или runtime callback. Не включать фоновую отправку автоматически.

## Что выполнить следующим вертикальным этапом

1. После общего build/test добавить тип exact DNS answer evidence: адрес/семейство/TTL/CNAME, actor и query path. Версии/context immutable.
2. Расширить существующий bound probe так, чтобы запрос действительно использовал полученный IP при сохранении SNI/Host и TLS. DNS-only не даёт PASS.
3. Один executor/одна комбинация/один сервис. Не менять всех провайдеров и всё ядро одновременно. Для запуска через Xray понять target resolution vs proxy server resolution на pinned version.
4. Проверить безаварийный preview/readback/rollback и точный client scope. Только потом включить automatic selection пар в существующий reconciler.
5. При community интеграции pin policy и highwater digest сохранять атомарно; нельзя использовать счётчики с непроверенным объектом Verified. Поле EligibleForApply всегда false у hint, пусть exact checker создаёт отдельный local proof.
6. Отдельный PR для consent, upload queue и aggregator. Никакого PAT в бинарниках, нового production endpoint без разрешения, custom-domains upload по общей галочке.

## Матрица проверок и артефакты

Сводная матрица из28 сценариев в DNS_COMMUNITY_UNIFIED_DC1_RU.md — будущие gates, не список якобы пройденного.
В комплекте: `logs/commands.json`, raw per-command stdout/stderr, `recipehints-go123.jsonl`, `browser-dc1.json`, validation scripts. Browser использует фиктивный backend и запрещает внешние запросы. Отдельный HTML не входит в production web и не подменяет DNS проверки роутера.

Собрать свежие ELF только после полного target toolchain gate. Хеши новых ELF не копировать из AWG31 baseline. Обновление README/status/version/build identity делать по реальному SHA. Релиз, kernel modules и router HIL — самостоятельные подтверждённые этапы.

В финале каждого PR сохранить источник и отчёт, указать exact commands/exit и ещё не выполненное. Не оставлять работу только в сообщении чата или несуществующем sandbox-архиве.
