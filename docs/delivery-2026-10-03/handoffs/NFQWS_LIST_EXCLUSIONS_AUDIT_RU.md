# NFQWS: границы list-mode и исключений

Дата: 2026-10-08. Основание: пользовательская поправка
`RAZVILKA_LIST_MODE_EXCLUSIONS_CORRECTION_2026-10-07.md`.
Это ограниченный аудит, не разрешение запуска и не результат HIL list-mode.
Процессный владелец `7b808ec` и исправление гонки `0f9c223` сохраняются;
ROOT принял их как `28e8a7e` и `5e54926`. Их проверки доказывают только
указанные процессные свойства, а не новый контракт списка.

## Зафиксированный исходный код

Проверены первичные исходники `bol-van/zapret2` на commit
`6b6c63e3385fa73f8af3be4a69171e947f5a319d`, уже названном в RESEARCH handoff.
Ссылки ниже содержат этот commit, не плавающий `master`.

| Источник | Установленное поведение |
| --- | --- |
| [hostlist.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/hostlist.c#L235) | `HostlistCheck_` проверяет исключения прежде включений. Все пустые include-коллекции означают успешную проверку. Обычная запись охватывает поддомены; префикс `^` задаёт строгое совпадение, проверяемое в `SearchHostList`. Ошибка stat/open при reload оставляет прежнее содержимое в памяти. |
| [ipset.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/ipset.c#L222) | `IpsetCheck_` также проверяет исключения прежде включений и разрешает пустые include-коллекции. При переданном reverse IP проверяется и другая сторона соединения. Отсутствие обеих коллекций тоже разрешает профиль. |
| [desync.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/desync.c#L212) | Обычный hostlist-профиль требует известного имени. Auto-профиль после L3/L4/L7/IP-фильтров выбирается по известному имени независимо от include. Отрицательная hostlist-проверка запрещает tampering; обучение возможно для несовпавшего, но не исключённого имени. Перед добавлением имя снова проверяется. Поиск продолжает перебор профилей. |
| [nfqws.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/nfqws.c#L2504) и [params.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/params.c#L316) | Auto-файл регистрируется как include и открывается для дополнения. `--new` создаёт новый профиль с пустыми коллекциями; списки предыдущего профиля автоматически не наследуются. |
| [pools.c](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/pools.c#L393) и [params.h](https://github.com/bol-van/zapret2/blob/6b6c63e3385fa73f8af3be4a69171e947f5a319d/nfq2/params.h#L97) | Пустота определяется содержимым коллекций, а не наличием аргумента или файла. Непустой exclude влияет на выбор hostlist-профиля, но не превращает пустой include в положительный список. |

Это анализ указанного upstream. Reviewed ARM64 payload
`keenetic-payload-1.3.1`, executable SHA256
`0c97153a2cc72392776fc550bf7be1cec77bc5db2505ab5b9dbc6d071e739c09`,
имеет отдельный manifest и wrapper source commit
`077f9af6068cd3380527085ca351b503a2dcf926`. Уже записанное RESEARCH ограничение
его build provenance сохраняется: точный upstream commit сборки не установлен.
Поддержка строгого `^`, пустых списков, reload и профилей этим конкретным
бинарником требует отдельной проверки ROOT/RESEARCH. Нельзя подменять её
сходством версии или detached manifest DTO.

## Следствия для нового контракта

Это требования RAZVILKA и выводы аудита, а не дополнительные свойства upstream:

- Пустой активный список означает отсутствие NFQ capture/Start. Наличие
  `--hostlist=empty-file` или названия `MODE_LIST` этого не обеспечивает.
- Каждый профиль, включая каждый `--new`, должен получать те же действующие
  host/IP исключения. Исключение только в первом профиле допускает совпадение
  другого профиля. Запрещён профиль со стратегией без своего положительного
  ограничения и профиль, превращающий «все выбранные устройства» в catch-all.
- Простое сочетание `--hostlist` и `--hostlist-auto` не ограничивает обучение
  активным списком. До появления проверенного ограничения входного потока и
  каждого события обучения auto не допускается новым production builder.
  Нельзя выдавать результат обучения за активацию пользовательского правила.
- Доменные и IP включения внутри одного профиля нельзя трактовать как общий
  OR всех пользовательских правил: IP-фильтр проверяется до hostlist.
  Разделение профилей требует одинаковых глобальных исключений в каждом.
- Exact domain и domain+subdomains сохраняют разную семантику. Для указанного
  upstream это `^example.org` и `example.org` соответственно. Service ID
  раскрывается только актуальным общим компилятором; NFQWS не знает service ID.
- Неизвестное имя, ECH и общий CDN-IP не дают права расширить доменное правило
  до IP capture. Если пересечение с исключённым доменом нельзя достоверно
  ограничить, спорная часть отклоняется с причиной. UDP/IP правило допустимо
  только как явно поддержанное активное IP/CIDR правило с выполненными
  исключениями, а не как обход неизвестного домена.
- Живой reload файлов не является атомарным применением Store/DNS/exclusion
  revision и не доказывает прекращение уже отслеживаемого соединения.
  Изменение исключений требует управляемого перехода известного владельца;
  глобальная очистка conntrack не допускается.

## Что сейчас имеется в RAZVILKA

Проверено на NFQ owner HEAD `0f9c223`, без правок чужих областей:

1. `network_policy_manager_nfqws_assembly.go:nfqwsExecutionCommandMatches`
   разрешает только закрытый набор существующих process/candidate аргументов.
   Ни hostlist, ни ipset, ни auto аргументы туда не входят. Активный командный
   matcher использует ту же чистую lexical проверку. Отказ сохраняется:
   добавление этих флагов без семантического compiler proof недопустимо.
2. `nfqws_scoped_owner.go:CompileNFQWSScopedPlan` строит capture по supplied
   ingress/source/destination CIDR/protocol/port и отклоняет `Route.Domains`.
   DNS-derived IP прямо не считается domain-dispatch authority. Этот compiler
   не доказывает происхождение CIDR из активного списка и не вычитает новый
   effective resource exclusion: эту обязанность должен выполнить DEFAULT
   до передачи trusted immutable intent.
3. `NFQWSScopedSpec` и resources содержат typed NetworkIdentity, candidate,
   command/session и revision общего Plan; отдельного frozen include/exclude
   образа сейчас нет. Сам hash argv и SAME8 не являются list-mode proof.
4. Legacy adapter Stage/Activate пишет user.list/ipset.list и использует stock
   init flow. Новый процессный владелец не подключает его автоматически.
   Его legacy поведение не получает новый production статус.
5. CORE-owned `engineconfig/nfqws_mode.go` распознаёт старый MODE_ALL для
   отображения; StageNFQWSMode уже не разрешает all, но допускает auto с
   allowDiscovery. `guided.go` ещё предлагает MODE_ALL. CORE уведомлён;
   owner NFQ не меняет эти файлы и не считает label/boolean доказательством.

## Нужный seam без нового issuer

DEFAULT владеет общим list compiler и обоими existing execution records;
CORE — реальным Store/config/control/consent review. Новый NFQ builder должен
потреблять их исходное retained review, а не создавать параллельный реестр
разрешений, принимать callbacks от публичного caller или восстанавливать
разрешение из DTO.

Минимальный frozen compiler input: существующая policy revision; digest
эффективных исключений с сохранённым manual/RU provenance; положительные
правила со scope; отдельно canonical include/exclude host/IP образ каждого
профиля; точные принадлежащие этой генерации file references/content hashes;
reviewed payload/candidate и SAME typed NetworkIdentity. Финальную форму
полей задают CORE/DEFAULT после их коррекции схемы, не этот audit.

Существующие BeforeStart/WithStart/Current/Prepared/WithTransfer/
PublishTransferACK и fresh CORE committed guard проверяют актуальность этого
же Store review при своих реальных границах. Digest только идентифицирует
образ; он не заменяет актуальный источник. После D fresh bounded operation
проверяет действующие исключения через реальный CORE guard. Cold restore и
stale Apply не могут вернуть образ, запрещённый уже принятой ревизией.

Списки принадлежат generation owner и проверяются как реальные файлы.
Произвольный путь в argv, доступный для сторонней записи include/exclude или
старый auto-файл не допускаются. Strategy selection меняет только tampering
в пределах compiler input. Отдельный retirement исходного process owner
остаётся после фактического Stop/ECHILD/parent ACK и COMMON cleanup/LAN-last.

## Следующая проверка и границы этого pin

После finished schema/compiler pins: meaningful модели пустого/несовпавшего
списка, exact/subdomains, исключения во всех профилях, stale revision до
Start/CAS/final ACK, overlapping positives и auto event без include. Затем
ROOT проверяет реальный reviewed binary на TCP/UDP, невидимое имя/CDN conflict,
обновление исключений при живом соединении и restart/restore. До этого
domain-list/auto enforcement не объявляется реализованным или проверенным.

Этот pin меняет только данный handoff. Go тесты не требуются для текстового
аудита; новых Windows/Linux/native/router эффектов он не запускал. Прежние
логи и статусы не переписаны.
