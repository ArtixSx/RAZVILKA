# Codex: продолжение UPDATE4, версия 0.18.2-repair.4

База REPAIR2 `3d5ac5c7aef7a505a46ea5b0f6fd1241e5a87dcc`; точный новый commit в COMMIT
и отчёте поставки. Использовать FULL/SOURCE или Git bundle, не переустанавливать
DC1/rc.4 main и не накладывать фрагменты AUTO3 повторно. Remote не изменён.

## Уже сделано

Каналы stable/preview; устойчивое сравнение версий; ETag и Retry-After release check;
адресный opkg upgrade с повторным чтением версии; проверки неоднозначных артефактов;
refill по дефициту резервов; сохранённые паузы источника; guarded обновление
применённых адресных правил; восстановление при отмене с отдельным контекстом;
режим NFQWS2 LIST/AUTO в черновике и выбор базовых групп в мастере.
Сохранены предыдущие starter/bulk/WARP/catalog/UI и rc.6 forwarding repair.

## Повтор программных проверок

Go из go.mod (1.26.5 toolchain), Node. На отдельном Linux-стенде:

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

check.sh делает четыре сборки и изолированный rehearsal. Не запускать на live router.
Новые package-тесты: updatecheck/channel_test.go, components/update_integrity_test.go,
providerfeed/refill_test.go, dataplane/address_refresh_test.go,
engineconfig/nfqws_mode_test.go, onboarding/selection_test.go,
app/maintenance_update4_test.go. JS: scripts/test-maintenance-ui.mjs.
HTTP/Chromium scripts в validation внешнего комплекта — изолированное состояние;
не использовать учётную запись реального роутера.

## P0: именно автоматическая установка, ещё НЕ выполнена

Не заменять закрытый automatic_install=false на true и вызов opkg.
1. Trust bootstrap от владельца: подпись manifest, версия/срок/архитектура/совместимость,
   постоянный highwater sequence/digest, ротация/отзыв ключей, старый рабочий каталог.
   Checksum не равен криптографически доверенной публикации. Тестовые ключи не production.
2. Immutable план всей транзакции: программа + frontend + конкретные версии движков,
   старые пакеты и зависимости, init/hooks/конфиги, права владельцев. Сейчас опkg
   скачивает разрешённый пакет, но не имеет доказанного полного rollback зависимостей.
3. Сначала подготовка и проверка кандидата; активация только в согласованном окне,
   с живым сервисным подтверждением и доступной LAN-панелью. Внешний supervision
   должен вернуть старый комплект, даже если основной процесс не стартовал.
4. Отложенная установка, отмена, смена WAN/ревизии/владельца, недостаток памяти,
   rollback-failed, карантин неудачного выпуска. Не считать номер версии процессом
   с новым бинарником: сопоставлять installed/running build/config identities.
5. Выбранный канал относится к приложению, не автоматически ко всем внешним движкам.
   Preview только explicit opt-in. Не делать downgrade local repair.* через обход сравнения.
6. Возможность точного обновления зависимости и полный план миграции схем Sing-box/Xray.
   Поддержанные поля генерируются под установленную версию, не под latest docs.

## P0: адреса и endpoint

1. UPDATE4 при неполном DNS сохраняет ВСЮ старую редакцию. Улучшить до per-domain
   provenance+TTL+CNAME+resolver+family+bounded grace без бессрочного накопления адресов.
   Постоянный NXDOMAIN одного необязательного домена не должен блокировать всё обновление.
2. Отдельно endpoint домена самого VLESS/AWG/USQUE и адреса целевого сервиса.
   Literal server-IP нельзя вывести из старого ключа: нужна обновлённая разрешённая
   подписка/конфигурация. Изменённый профиль — новая identity, без старого PASS.
3. При IP-ротации выбранного node доказать новый точный egress и service. Текущий
   manager refresh ещё не универсальный автопереключатель endpoint каждого транспорта.
4. У USQUE/WARP различать reread/enroll и register. Не выпускать новый аккаунт из-за
   DNS timeout. Новая регистрация с отдельным согласием/лимитом и журналом неопределённого исхода.
5. После смены адресов не обрывать совместимые старые соединения без нужды;
   неполный новый набор не объявлять успешным. Отдельные IPv4/IPv6 и физические клиенты.
6. Проверить реальный scope у глобального автохостлиста: MODE_AUTO обнаруживает
   дополнительные домены, а шесть карточек интерфейса не ограничивают его сами по себе.

## P1: источники/резерв/наблюдение

- Refill не гарантирует новый материал, если источник не изменился или лимит выборки
  возвращает те же первые строки. Нужна ротация большой выдачи и обслуживание лимита
  NodeStore с защитой активного/сохранённого/приостановленного/rollback узла.
- Retry-After источника durable; retry release metadata пока process-local. Нужен общий
  bounded transport budget, jitter и сохранение cooldown для рестарта без overload.
- Normal selected batch до64 всё ещё держит admission на партию. Унифицировать с
  all-vless и допуском аварийных задач после cleanup. Durable cursor/idempotency/resume.
- Внешний ONLINE/TCP PASS только hint. Не передавать стороннему checker приватные UUID,
  пароли и адреса своих сервисов. Полный локальный протокол+egress+сервис отдельно.
- Уточнить разделение 304 origin/credential expiry и свежести health; stale каталог
  может сохранить active material, но не создаёт новое разрешение при явном отзыве.
- Обновление уже импортированных доменных definition: исходный digest, diff и
  постоянное согласие на изменения внутри установленного охвата; новые зоны сначала
  отдельно оцениваются. UPDATE4 не делает cron-переимпорт всех community definitions.
- NFQWS2: compiler typed стратегии с версиейLua/blobs, last good, негативные контроли,
  локальное испытание нового профиля и scoped commit/rollback. MODE_AUTO не заменяет
  этот механизм. Не применять скачанный shell из сообщества.

## Матрица следующей аппаратной приёмки

1. Fresh master: шесть доступных, выбраны YouTube/Discord, остальные не активированы.
2. LIST→AUTO только после согласия, staged неизменные прочие аргументы, cancelled POST.
3. Повторное чтение после reboot сохраняет subset/channel/режим без самовольного Apply.
4. VLESS A отказал; B подтвердился; новый поток нужного клиента идёт B; второй клиент нет.
5. Все резервы исчерпаны: разрешённая подписка обновилась, узел C проверен и применён.
6. Подписка 429/503, Retry-After, reboot: нет раннего повторного запроса.
7. Источник временно недоступен/304/пустой: текущий материал не уничтожен.
8. DNS service IP изменился при неизменном WAN: новые scoped правила, old rollback.
9. Один домен timeout/NODATA/private: refresh не сносит действующий набор.
10. Смена WAN/ревизии/Stop/SafeMode во время DNS: отмена до записи; cleanup завершён.
11. Отказ health после replace/cancel: старые правила реально восстановлены или
    rollback-failed показан, а не «checked/работает».
12. Stable/preview; rc.6→rc.10, stable против rc, downgrade, чужойreleaseurl/draft.
13. Force при GitHub rate limit, 304 без cache, устаревший готовый download, сменаканала.
14. opkg update источникаfail / list-installedfail / listfail не «компонентотсутствует».
15. named upgrade code0 unchanged / reported downgrade не «успех»; другие пакеты целы.
16. Duplicate checksums/ZIP, чужой репозиторий, поломанныйreceipt — отказ без обхода.
17. Окна при постоянноdueсервисах, pending prepare readback, нет update — нетdownload.
18. Физический WAN reconnect/reboot/MIPS/малоRAM/24–72ч с закрытым браузером.

Каждый результат привязать к commit, SHA бинарника, ядру и сценарию. Не переносить
аппаратные результаты старой rc.5 на UPDATE4. Если доступа к роутеру/ключу нет,
отметить аппаратные пункты отдельно, не выдавать mock за hardware и продолжить
все независимые программные этапы. Итог — полный проект, патч, бинарники,
контрольные суммы и первичные журналы, не один HTML и не список обещаний.
