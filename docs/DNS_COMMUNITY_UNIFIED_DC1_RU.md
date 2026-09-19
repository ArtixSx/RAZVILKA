# Единый план: DNS, маршруты и рекомендации сообщества

> Исторический документ конкретного этапа. Версии, команды и состояние функций
> ниже относятся к тому этапу. Сейчас используйте [план](ROADMAP.md),
> [текущий статус](CURRENT_STATUS_RU.md) и [установку](INSTALL_RU.md).

Редакция DC1, 2026-09-13. Дополнение к существующему RAZVILKA master-plan §§4,10,48,49,53,55 и AWG31-WARP handoff. Не новый независимый roadmap; не отменяет сохранность working baseline.

## 1. Цель и неизменяемое основание

Установил → один раз задал устройства, сервисы, способы, доверие, расписания и согласия → дальше добавляешь/удаляешь сервисы. Все необходимые проверки, выбор, обновления и восстановление выполняются на роутере независимо от браузера. «Всегда работает» означает самостоятельно восстанавливается в пределах доступных разрешённых путей; отсутствие любого работоспособного пути не скрывается.

Сохранить один scheduler/reconciler, operation gate, NodeStore, Evidence, dataplane и transaction pipeline. Не устанавливать внутри RAZVILKA второй z2k/AWG Manager/HydraRoute/3X-UI. Не снимать Safe Mode, ownership, TLS и ограничения под видом автоматизации.

Главная — наблюдение/отклонения/очередь. Сервисы — настройка и сетка. AI — категория представления, не общий принудительный маршрут. DNS-провайдеры — существующая вкладка DNS. Вкладки обходов сохраняют полный lifecycle; сайт не заменяет backend.

## 2. Статусы, которые нельзя смешивать

| Идея | DC1 |
|---|---|
| Обычный resolver отдельно от Smart DNS | Метаданные добавлены; gateway не становится безопасным/рабочим из-за названия |
| Xbox / Malw / Comss | Настроенные шаблоны для явной диагностики; не automatic production |
| GeoHide / Control D Redirect | Ненастроенные шаблоны; endpoint/API/account не выдуман |
| Сравнение DNS для произвольного сервиса | API-код и UI: A/AAAA главного HTTPS-сценария, только DoH, нет live Apply |
| Точное DNS→адрес→TLS→сервис через выбранный путь | Предстоит; старая проверка NFQWS2/узла не расширена неявно |
| Компиляция DNS policy в Keenetic/Xray/Sing-box/локальный resolver | Предстоит; платформенный запрет остаётся |
| Перебор целых комбинаций/резерв/TTL/кэш | Предстоит |
| Канонический рецепт и signed catalogue shortlist | stdlib-библиотека добавлена и отдельно протестирована, не включена в app |
| Облако ingest + GitHub publication + nightly sync | Предстоит; никаких учётных записей или сервисов не создано |
| Обмен результатами, onboarding consent | Предстоит; отправка полностью отсутствует |
| Сохранённый WARP/AWG31 baseline | Не заменён; его аппаратные и updater-пробелы остаются |

## 3. Три разных свойства DNS

Не использовать одно поле location, которое одновременно означает всё.

1. **Кто разрешает назначение:** router/client resolver; локальный proxy engine; удалённый proxy server.
2. **Как запрос достигает DNS:** текущий системный путь; конкретный существующий туннель; отдельный служебный/резервный выход.
3. **Как идёт прикладное соединение:** direct WAN; NFQWS2; WARP/AWG/USQUE; точный proxy node; Smart DNS gateway либо явно проверенная композиция.

DoH, выполненный самим локальным Xray через VLESS, не означает, что DNS-запрос выполнял удалённый DNS-модуль сервера. Обратный случай: передача домена VLESS-серверу может сделать выбор DNS на роутере незначимым для назначения. Неподконтрольный удалённый DNS не объявлять управляемым.

**Xray:** настройка built-in DNS сама по себе не гарантирует резолв назначения через него. В актуальной документации `targetStrategy=UseIP` относится к цели VLESS, тогда как `sockopt.domainStrategy=UseIP` может разрешать hostname самого VLESS-сервера. Поддержку каждого поля проверять по точной версии Xray. Для другой версии явно unsupported, а не тихая подмена. `skipFallback` исключает этот DNS из fallback для чужих запросов, а не запрещает все fallback; `finalQuery` — отдельная семантика.

**Smart DNS:** физический маршрут до возвращённого gateway может быть WAN, но логически это сторонний proxy, не полностью локальный/direct обход. Нельзя считать `Xbox + NFQWS2` дешевле/приватнее из-за отсутствия полноценного VPN. Если разрешённый Smart DNS без NFQWS2 уже подтверждён, NFQWS2 не добавляется ради одинаковой строки в UI.

## 4. Registry провайдеров

Разделить роль (resolver/filtering/uncensored/smart-dns/negative/custom), trust class (operator/community/account/user), транспорт и подтверждённые возможности. Community — уровень происхождения, не DNS-протокол.

Для каждого: ID, URL документации, проверенная дата/ревизия, endpoint и bootstrap, account/IP-authorization requirement, privacy/terms, список заявленных сервисов только hints, способность к v4/v6, срок пересмотра, отдельные результаты локальных тестов.

Malw/Comss могут одновременно фильтровать и перенаправлять отдельные сервисы. Не смешивать их с Cloudflare/Google как взаимозаменяемый fallback без согласования политики. Control D Redirect — отдельный аккаунтный продукт, не свободный `p0`. Hosts/списки GeoHide — данные о доменах/перенаправлениях, не доказательство адреса DNS или права использования gateway.

Регистрационные WARP/USQUE и обновительные GitHub/Entware домены обслуживаются отдельно. Применение DNS для Instagram не должно менять загрузку update manifest или enroll API. В DC1 Smart DNS закрыты для USQUE bootstrap. Другие WARP пути необходимо проверить отдельно: данное поле не гарантирует, что вся программа уже соблюдает это ограничение.

## 5. Минимальный сквозной Resolver Lab — следующий этап

1. Зафиксировать service definition revision/scenario, policy revision, devices, network generation, engine/strategy/node version, consent.
2. Проверить разрешение DNS-запроса и прикладного контроля: при запрете direct не отправлять пользовательский домен обычным путём ради теста.
3. Один–три разрешённых DNS-кандидата; один–несколько адресов в пределах общего бюджета. Никакого полного DNS × node × strategy × service произведения.
4. Получить A/AAAA/CNAME/TTL через точный выбранный resolver и записать request path. Разные ответы сами по себе не доказывают перехват.
5. Соединиться **именно с адресом из этого ответа**, сохранив исходные SNI/Host и проверку сертификата. Повторное системное разрешение, pooled connection прошлого кандидата и непроверенный redirect запрещены.
6. Проверить точный engine/interface/mark/queue/outbound, handshake/egress при необходимости, и семантику нужного сервиса. Для NFQWS2 не требовать внешнего нового IP; для WARP сохраняется соответствующий trace. HTTP 200/403/429/redirect интерпретируются по сценарию, не все как PASS.
7. Несколько адресов/семейств — явное покрытие. Один успешный адрес не подтверждает остальные; один web-check не подтверждает API, auth, видео, QUIC, голос или платные функции. Не делать платные запросы/использование account cookies автоматически.
8. Повторить победителя, сравнить с контрольным разрешённым путём. До live Apply результат only candidate.
9. Скомпилировать согласованную DNS+traffic политику для реально поддержанного executor. Проверить конфликты, лимиты, ownership, scope, staged candidate и rollback; повторно проверить все revisions непосредственно перед commit.
10. Read-back, convergence локального DNS, exact active-route/LAN post-check. Пробы самого роутера не выдают себя за трафик выбранного телефона.

DC1 выполняет часть шага 4 без TTL/CNAME-проекции в API. Результат DNS-only не потребляется как service proof.

## 6. DNS executor и общие домены

Выбор исполнителя по capability: NDM Keenetic, согласованная интеграция внешнего AdGuard, собственный local stub, DNS внутри Xray/Sing-box. Один owner. Не занимать чужой port53, не править глобальный resolv.conf, не менять неизвестные правила.

Считать количество занятых/новых/стейджинговых записей. Указанный в присланном PDF лимит 8 DoH + 8 DoT — историческое наблюдение, не универсальная аппаратная константа. Если ресурсов нет — сообщить ограничение или предложить согласованный другой executor, не удалять сначала рабочие записи.

`facebook.com` может использоваться и Instagram, и Facebook. Нужны references/refcounts; отключение одного сервиса не удаляет общую запись. Разные DNS/устройства для одного домена требуют поддержанного разделения либо явного конфликта. Exact/suffix semantics подтверждать на платформе; не включать всю `googleapis.com`/CDN по одному новому имени.

Кэш — отдельное состояние `pending_cache_convergence`. Управлять только своим кэшем. Роутер не может гарантированно очистить кэш любого приложения, разорвать его старый HTTP/3 поток или навязать DNS приложению с private DoH. Не отключать IPv6/QUIC глобально ради зелёной проверки. Кэш production включён; lab fresh-query не является запретом upstream cache.

## 7. Автопилот комбинаций

Общее правило — сохранить здоровый LKG. Далее разрешённые local/community shortlist для конкретного сервиса/сети, а не вечная цепочка DNS→NFQ→WARP→VLESS.

Если исправен туннель, но не один сайт — попробовать совместимый разрешённый DNS-кандидат с тем же способом. Если все варианты DNS не помогли — это не строгое доказательство DPI; остаётся typed uncertainty и выбор другого разрешённого пути. Ошибка DNS не даёт права создавать новый WARP-account, удалять узлы или перезапускать общую подсистему.

Одинаковые subscriptions скачиваются один раз; Node+DNS проверяется отдельно на сервис. Не нужно тестировать каждый из 500 узлов с десятью DNS. Выбрать до 2 DNS-предпочтений для перспективного узла, после локальной проверки протокола. При generic HTTPS разрешении невозможно обещать полный результат неизвестного приложения.

Winner identity включает service/scenario/domain-set revision, WAN generation, family, DNS provider+revision+actor+query path, engine/node/strategy/runtime digest, target/answer coverage, timestamp/expiry. Истечение evidence запрещает новый commit, но не является приказом удалить активный маршрут.

## 8. Коллективный каталог стратегий

### Продукт

Облако сокращает порядок тестов, не управляет роутером. Local LKG → подходящие community top3 → встроенные безопасные recipes → ограниченное локальное исследование остальных совместимых вариантов. Числа — начальный экспериментальный budget, не обещанные SLO.

Рецепт — каноническая типизированная структура с ссылками на поддержанные локальные стратегии/assets, а не произвольный shell или кусок Lua. Изменившиеся порядок стадий, повторы, payload hash и реальные wire-различия нельзя схлопывать ради дедупликации. В DC1 hash покрывает имеющиеся поля, а StrategyID ссылается на локальное определение; неизменяемость/полный hash определения предстоит обеспечить в Strategy Registry.

Публиковать generic route pattern/DNS/provider/strategy. Никогда не отправлять VLESS URI, UUID, WARP/AWG/USQUE ключи, secret source URL, адрес чужого частного узла, полный пользовательский domain list.

### Инфраструктура

GitHub: schema, reviewed recipes, статические compact snapshots, revocations, Releases/Pages/mirror как заменяемая доставка. Не писать файл/Issue от каждого роутера. Read-only получение должно работать без PAT на клиенте.

Отдельный HTTPS ingest: принимает добровольные отчёты, rate limits, дедупликация, временное агрегирование, quarantine подозрительных данных. Publisher с минимальными отдельными правами подписывает snapshot. Секрет GitHub App/PAT не находится на роутере; подпись catalog ключом не равна подписи новых бинарников и не даёт права исполнять код.

Ключ издателя закрепляется отдельно. Нужны persist highwater sequence + digest (равный sequence с другим payload тоже конфликт), expiry, revocations, ротация ключей, last accepted snapshot. DC1 предоставляет проверку подписи/минимального sequence и expiry, но не это персистентное хранилище/скачивание/публикацию.

Никаких production ключей, ingest URL или нового репозитория этой итерацией не создано. При отсутствии облака используется локальный каталог и LKG; это не получение новых данных без сети.

### Приватность/согласие

Три независимых разрешения, по умолчанию выключены: получать рекомендации; отправлять результаты для публичных каталоговых сервисов; публиковать новый собственный recipe. Дополнительно opt-in на укрупнённый регион/ASN. Отказ от отправки не лишает локальных функций или чтения каталога.

Нельзя обещать полную анонимность: HTTPS-сервер ingest видит исходящий IP, а service ID + время + ASN могут коррелировать установку. Собирать минимум, не логировать сырые IP, определить TTL и deletion policy. Локальная случайная identity и подпись отчёта дают дедупликацию, но **не доказывают независимого человека**. Не использовать текущую VPN-геолокацию как реальный адрес пользователя.

Custom/private service по умолчанию local-only, даже если имя прошло синтаксический validator. Публикация требует отдельного preview и решения. Отзыв consent очищает ещё не отправленную очередь; условия удаления уже опубликованных агрегатов описать честно.

### Рейтинг

Учитывать успехи И отказы, scenario/family/runtime/schema, давность и совпадение контекста. ERROR/INCONCLUSIVE не становятся обычными отрицательными голосами и учитываются отдельно. Частота отчётов одной установки не равна количеству пользователей; повторные mirror observations дедуплицируются.

Wilson/decay — эвристика, не доказательство качества при зависимых samples. Выбор только победителей создаёт selection bias: нужен знаменатель проведённых испытаний, классы причин и ограниченное исследование без вреда активному трафику. DNS-provider trust не повышается одной популярностью. Anti-Sybil, moderation, diversities и abuse tests обязательны перед широким выпуском.

Отравленный signed catalog может заставить тратить ресурсы, рекомендовать нежелательный third-party provider или раскрывать metadata даже при обязательном canary. Защита — policy allowlist, строгий parser, resource cap, quarantine и review, а не обещание «максимум одна безвредная проба».

## 9. Расписания

В мастере человек выбирает timezone, дни/окно обновления программы и отдельно движков, каталогов. Автоматическое обслуживание подписок и аварийный failover — круглосуточно, не ждать ночи. Скачивание hints ночью не запускает массовый Strategy Lab и не переключает здоровые сервисы.

Одна очередь: дедлайны/cancel/idempotency, shared resource budget, jitter/backoff, приоритет восстановления, low-RAM профили. Обновления программ требуют подписи, совместимого комплекта binary/config/dependencies и независимого отката; check/prepare не равно install.

## 10. Единая следующая очередь

| Этап | Изменение | Приёмка |
|---|---|---|
| DC0 | Повторить общий Go1.26.5 build/test, новые DNS/app tests | Не ослаблять go.mod, gates или assertion ради зелёного результата |
| DC2 | Bound DNS + exact destination + TLS/service scenario | Wrong SNI/cert, wrong route и DNS-only никогда не PASS |
| DC3 | Scoped executor, conflict/readback/TTL/cache | Не затронут контрольный клиент/сервис; partial failure откатывается |
| DC4 | Резерв и автоматическая пара DNS+traffic | Один scheduler, closed browser, stale generation и manual override |
| CI1 | Подписанный каталог + persist highwater/expiry | Нет rollback/equivocation/unknown-key bypass; offline LKG |
| CI2 | Local recipehints подключить в ограниченный shortlist | Только меняет порядок проб; не расширяет trust или service scope |
| CI3 | Consent/report queue + ingest prototype | Никаких private domains/keys; default off; revoke; retention |
| CI4 | Агрегатор/публикация/рейтинги | Poisoning/Sybil/rate-limit tests; операторские ключи отдельно |
| AWG/UPD | Сохранённый AWG31-WARP handoff, modules/updates | Exact-model/ABI + аппаратный canary; не слепой opkg upgrade |

Не пересоздавать NodeStore/сайт/базовый планировщик; расширять существующие модули. Новые backend paths не называть готовыми по одному unit-тесту.

## 11. Сводная матрица обязательных последующих тестов

1. Три DoH × A/AAAA укладываются в budget; четвертый отклонён до сети.
2. Ненастроенный/negative/private provider блокирует всю партию до первого запроса.
3. Смешанный public/private ответ, неверная family, ID/question/CNAME chain отвергаются.
4. DNS `resolved` не становится Service PASS или правом Apply/re-registration.
5. Один адрес успешен, остальные неизвестны: coverage/partial, не полный PASS.
6. Одна функция сервиса работает, другая нет: independent verdict, не общий ✓.
7. Правильный IP/HTTP200, неправильный сертификат/SNI: отказ.
8. VLESS проксирует домен и резолвит удалённо: локальный DNS-кандидат не получает ложный credit.
9. Bootstrap hostname VLESS vs destination hostname не путаются.
10. DNS и traffic на разных egress при IP-authorized provider: явная несовместимость.
11. WAN/DNS/service/runtime revision изменились в ходе canary: старый commit запрещён.
12. Истёк TTL/кэш клиента: pending, не WARP registration.
13. Удалён Instagram, остался Facebook: общая запись не теряется.
14. Заполнен лимит DNS/порт53 чужой: не удаляется baseline и не запускается второй owner.
15. Private-DNS разрешён, но policy `geoip:private` его блокирует: ограниченное owned exception или конфликт, не глобальный unblock LAN.
16. У пользователя direct запрещён: ни контроль, ни DNS-запрос не утекли напрямую.
17. Здоровый WARP + DNS-error сайта: account unchanged; API quota unaffected.
18. Good LKG + новый лидер community: нет churn рабочего маршрута.
19. Неверная подпись/key/schema, повтор JSON key, oversize, expired/future catalogue: reject.
20. Rollback sequence и одинаковый sequence с другим digest: reject.
21. Signed но запрещённый provider/strategy: shortlist пуст; подпись не расширяет permissions.
22. 1000 голосов одного отправителя/сети не объявляются 1000 людьми.
23. Empty report buffer/revoke consent/custom domain: отсутствие отправки и утечки в logs.
24. Ingest/GitHub unavailable: active routes и local Lab продолжают работу.
25. Cache/source update не продлевает локальное service proof.
26. Отмена/logout/устаревший POST/retry не применяют старое намерение.
27. Clean install/old schema migration/неподписанный component update: safe failure.
28. Closed-browser HIL 24–72ч, WAN/reboot/OOM/потеря питания, два сервиса/два узла/контрольный клиент.

Это запланированные сценарии общей функции. Фактически выполненные DC1 проверки перечислены в CANDIDATE_DC1_RU.md и первичных логах.

## 12. Источники и граница фактов

- Пользовательский PDF Internet Helper: «DNS и hosts …», 6 страниц; историческая wiki-дата 2025-11-20. Он описывает альтернативные ответы и настройки, а не гарантированную поддержку всех WAN.
- Пользовательские кадры WARP generator и 3X-UI: свидетельствуют о полях интерфейса, не доказывают фактическую компиляцию/транспорт/скорость.
- Xray official DNS и VLESS documentation, проверено 2026-09-13: https://xtls.github.io/en/config/dns.html ; проверить точную поддержку targetStrategy/sockopt по версии core.
- Xbox operator: https://xbox-dns.ru/ ; endpoint https://xbox-dns.ru/dns-query .
- Malw operator: https://info.dns.malw.link/ ; endpoint https://dns.malw.link/dns-query .
- Comss operator: https://www.comss.ru/page.php?id=7315 ; https://www.comss.ru/page.php?id=15667 ; endpoint https://dns.comss.one/dns-query .
- GeoHide reference: https://github.com/Internet-Helper/GeoHideDNS . В этой итерации текущий DNS endpoint независимо не подтверждён.
- Control D reference: https://docs.controld.com/docs/custom-rules . Аккаунтные действия не выполнялись.

Перечисление провайдера и чтение документации не являются новым service/WAN test, гарантией бесплатной постоянной инфраструктуры или автоматическим согласием пользователя. Старые ответы о стопроцентно «подтверждённых» популярных DNS не переносить в metadata verified.
