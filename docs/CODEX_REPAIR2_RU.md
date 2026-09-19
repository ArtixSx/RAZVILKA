# Codex: продолжение единого repair.2

> Исторический документ конкретного этапа. Версии, команды и состояние функций
> ниже относятся к тому этапу. Сейчас используйте [план](ROADMAP.md),
> [текущий статус](CURRENT_STATUS_RU.md) и [установку](INSTALL_RU.md).

База rc.6 `cea4b6fec8a3fc807556a045c1c6446fa8932c9d`. Использовать итоговую
ревизию из отчёта/COMMIT поставки, а не восстановление DC1 или rc.4 main.
Эта ветка включает starter + VLESS bulk + setup/WARP/catalog fixes.
Не накладывать прежние fragments повторно. Сохранить пользовательские изменения.

## Сначала воспроизвести gate

Требуется настоящий Go 1.26.5 из проекта, Node.js. Не понижать go.mod/go.sum.
На Linux-стенде, не на живом роутере:

```sh
git status --short
git rev-parse HEAD
go version
go mod verify
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
node scripts/build-interface.mjs --check
sh scripts/check.sh
```

`check.sh` читает/проверяет исходники, выполняет 32 JS-набора, строит четыре ELF
и запускает изолированную установку с откатом. Первичный общий запуск в окружении
разработки мог упереться в бюджет оболочки на холодной кросс-компиляции; это не
результат финального gate. Использовать именно итоговый report с кодами команд.

Отдельные scripts validation из внешнего комплекта — HTTP на localhost с безопасным
изолированным состоянием и offline Chromium. Native browser navigation к localhost
в исходной среде блокировалось политикой браузера; это НЕ подтверждённый browser E2E.
В обычном Codex-окружении выполнить настоящий авторизованный browser→HTTP сценарий.

## P0 — реальное восстановление, не косметика

1. Два контролируемых VLESS A/B, два сервиса, отдельный исключённый LAN-клиент.
   Пройти мастер, проверить retained consent и scope после restart.
   Отключить A снаружи стенда (не сносить глобальные таблицы), закрыть браузер:
   повторный отказ → свежая проверка B → транзакция → фактический клиентский путь.
   Измерить время каждого этапа, gate wait, RSS/FD/CPU, per-service состояния.
2. При INCONCLUSIVE новая ветка только подготавливает резерв. Покрыть отдельные
   причины: неработающий direct control, DNS, endpoint, protocol, auth, egress,
   service predicate, timeout, cleanup/identity. Не делать `INCONCLUSIVE=FAIL`.
   Расширять автоматическое восстановление только отдельным обоснованным триггером
   и доказанным кандидатом. Fatal checker не запускает соседние процессы.
3. Унифицировать обычный selected batch и all-vless очередь. Первый до сих пор
   удерживает exclusive на всю партию. После очистки узла уступать аварийным задачам;
   новый ручной intent отменяет только правильную задачу. Не отпускать lock до cleanup.
4. Durable resume/idempotency для bulk — отдельный журнал. Сейчас закрытие страницы
   допустимо, restart процесса прерывает job. Повтор запроса после утраты ответа
   не должен создавать две партии; исключить неограниченное расширение snapshot.
5. Проверить rc.6 forwarding recovery на полном исчезновении собственной filter
   цепочки, при неизменном WAN. Отдельно partial/foreign правила, scope, NAT siblings,
   несколько адаптеров. Не удалять предохранитель, не flush всё ради теста.
6. Обслуживание не голодает от due сервисов; проверяется очередь при непрерывной
   нагрузке, дневной/ночной переход, timezone/DST, отмена/изменение политики,
   failed check → retry в том же окне, pending prepare → readback без повторной Create.
   Retry счётчик process-local для read/check, завершение durable; после рестарта
   повтор read/check разрешён, но это не семантика внешней регистрации.

Файлы: `internal/app/autonomy_worker.go`, `autonomy_recovery_helpers.go`,
`autonomy_maintenance.go`, `reconciler.go`, `node_bulk.go`, `node_checks.go`,
`internal/dataplane/nodecheck.go`, `policy_forwarding_repair.go`.

## P1 — довести пользовательский путь

7. Clean install: ровно шесть stock-групп; union 278 доменов. Список IP из upstream
   не добавлять как бы уже подтверждённую поддержку. Общие CDN явно пометить;
   одна веб-проба не подтверждает все приложения, использующие googleapis/amazonaws.
8. Upgrade: сохранить действующий пользовательский каталог, состояния, old/suspended
   маршруты, pin/источники. Изменение defaults не выполняет массовое удаление.
   При желании добавить отдельный preview→согласованная очистка неиспользуемого
   старого стандартного каталога, но не смешивать это с установщиком.
9. Первый master сохраняет base+selected extras одним CAS, без побочного Apply.
   GitHub import до завершения мастера должен обновить список extras, сохранив
   несохранённые поля. Reopen/retry/ref-changed/double-click не расширяют согласие.
10. Реальный GitHub: raw/blob URL, include-файлы, недоступность, лимиты, отмена,
    digest mismatch, expired preview, каталог/сессия изменились. Text/file path
    проходит без сетевого fetch. CIDR/probe relation требует самостоятельного
    сценария для приложений без DNS-имен; не приписывать ему веб-проверку.
11. WARP auto: disabled→dependent flags→enabled draft; обе TOS-галочки не меняются
    программно. Расхождение числа applied/draft сервисов и порога показать отдельно.
    Сейчас guide считает выбранные/разрешённые route поля; улучшить readback реально
    применённых сервисов, не понижая порог без согласия.
12. Native authenticated UI: cancel modal/input epoch, old401 after login, confirmed
    component plan, backend declined, pre/post-write refresh, update in another tab.
    Ошибки глобального rollback не скрывать при переключении движков.
13. Установка компонента: true install+start+profile+service proof отдельно. AWG kernel
    model/ABI/capability/matchingCLI delivery пока отсутствует; получить доверенную
    manifest-сборку и протестировать модуль на конкретном ядре до автозагрузки.
14. UI сейчас имеет один generator, но старые DOM IDs оставлены для контроллеров.
    Рефакторить их только с миграцией и тестами; не создавать ещё одну панель рядом.

Файлы: onboarding/*, catalog/nfqws2_starter.go, app/nfqws2_starter.go,
app/autonomy_api.go, community/custom_source.go, app/community_source.go,
web/setup-workflows.js, console-autonomy.js, awg-workspace.js, app.js.

## P2 — прежние большие идеи после работающего P0

15. DC2: exact DNS A/AAAA/CNAME/TTL → конкретный publicIP → выбранный путь → исходный
    SNI/Host → TLS/сценарий. Подтверждённое место разрешения локальное/движок/удалённое.
    DNS-only не даёт права Apply. Direct control допустим только политикой.
16. DC3/DC4: client-scoped DNS+route одна транзакция, conflicts/shared domains,
    cache convergence/readback/rollback, затем bounded pair selector. Не снимать
    DNS_LIVE_ADAPTER_UNAVAILABLE без исполнителя. Онлайн-популярность не local proof.
17. Community: consent opt-in, раздельные downloading/reporting, пользовательские
    домены не публиковать по общей галочке, rate limits/dedup, signedcatalogue+expiry+
    persistentsequence/digest+revocations, отсутствие PAT/owner key на роутере.
18. Ночная установка: signed compatible release/component manifest, полный старый
    комплект, атомарная активация и откат без работающего UI, карантин неудачного
    выпуска; read/check/prepare не объявлять готовой unattended установкой.
19. AWG/WARP: настоящие серверные ключи и формы только владельца, WAN/tunnel recovery,
    ограниченная registration с неопределённым результатом, модель/ядро/CLI,
    отдельные IPv6/UDP/media, без запрещённого отключения TLS или скрытого fallback.
20. Завершение: 24–72ч закрытый браузер, WAN/reboot/мало RAM/отказ источников,
    отдельные physicalclients и точная identity бинарника. Сохранить логи безсекретов,
    sourcecommit, checksum и явно непроверенные пункты. Никаких процентов готовности
    или гарантии «все сервисы во всех сетях» по HTTP200 на одной главной странице.

## Что отдавать следующим результатом

Полные исходники, отдельный patch от проверенной базы, git history, exact build ID,
package/checksums, report с командами/exit/версией окружения и аппаратной матрицей.
Не публиковать main/latest без согласованной приёмки и не передавать лишь отдельные
Go/JS-файлы вместо проекта. Инфраструктурные ключи/аккаунты требует предоставить
владелец; их отсутствие не мешает закончить все независимые программные проверки.
