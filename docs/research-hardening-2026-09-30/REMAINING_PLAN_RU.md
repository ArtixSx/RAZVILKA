# Остаток V2 после подготовленного hardening

Это продолжение существующего V2, не новый независимый план. Главная цель неизменна: **весь интернет согласованных домашних сегментов, кроме исключений; сервисы — индивидуальные переопределения**. Приоритет Xray → WireGuard → AmneziaWG сохранён.

## Нулевая итерация: принять настоящий код, а не галочки

Собрать точную полную копию через сборщик. Если текущий GitHub уже ушёл вперёд, перенести изменения по смыслу и не сбрасывать новые коммиты. Сравнить baseline/full CI, пройти добавленные repo-тесты. Особенно App/state integration, ownedfs cache, общий WG adapter и совместимость error wrapping. Изолированные тесты этого пакета не заменяют эти действия.

Закончить совместимость pending/installer receipts при downgrade. Новая программа не повторяет свою pending-operation; старая не знает её смысл. Нужен запрет отката при незавершённой компонентной операции либо независимый совместимый helper. Не ослаблять unknown-field decoder.

## 1. Xray — закончить первую вертикаль

Установка Xray и управляемого sidecar, строгий импорт VLESS REALITY/TLS RAW/TCP, native check фактического бинарника, canary, Apply, запись Store, readback и перезапуск. Registry fixes должны проверяться **до конца транзакции**, а не только допустимостью строки.

Проверить один выбранный клиент и отрицательный контроль второго, отсутствие DIRECT fallback, PID/start/config identity, endpoint protection, DNS/SNI/Host, TLS. Kill proxy, kill sidecar, исчезновение owned rule, смена WAN, restart/reboot, плохой кандидат, rollback. Временно локальный native-стенд допустим и полезен, но не доказывает работу через ISP/Keenetic.

Только затем XHTTP и другие transports. Документация upstream может менять названия/поля; не заменять network/method/publicKey/password по одной latest-странице. Матрица compiler → фактическая version/native fixture → маршрут. Не смешивать REALITY с транспортами, которые выбранная версия не поддерживает.

## 2. Generic WireGuard — native и несколько профилей

Испытать новый порядок canary на настоящем kernel/userspace WG: cold peer, keepalive off, scoped-only, mixed scopes, потеря ответа, cleanup. Разделять handshake, реальный data path и LAN client proof. Проверить, что адрес привязан к правильному временно созданному интерфейсу, особенно при одновременных live/candidate с одинаковым внутренним Address; источник сам по себе не заменяет пакетное доказательство.

Добавить хранилище нескольких профилей/резервов без дублирования секретов. Сохранить endpoint hostname/TTL/original identity, обновлять один pinned адрес после проверки. Private/site-to-site endpoint — только явно разрешённая область, не обход SSRF для внешних feeds. AllowedIPs не даёт all-LAN authority. IPv6-only и dual-stack — отдельные capabilities, не фиктивный PASS по IPv4.

## 3. AmneziaWG — совместимость, доставка и HIL

Точный runtime/CLI/module/ABI/vermagic/arch и оригинальный профиль; таблица поддержанных полей; реальный совместимый peer. Никакого произвольного insmod/rmmod с чужими интерфейсами. Userspace и kernel реализации не равнозначны по ресурсам. Новый preprobe снимает чужую Cloudflare-зависимость, но не доказывает AWG-поддержку удалённого сервера. WARP-compatible клиентские дополнения не равны полноценному AWG3.x peer.

## 4. Автопилот общего пути и отдельных сервисов

Единый capability registry и один coordinator, цели default/service. Здоровый LKG сохраняется. Рабочий NFQWS2 preferred отличается от NFQWS2-only; migration/consent не выводить из имени каталога. После подтверждённого отказа preferred допускает уже разрешённый резерв, only — нет.

Универсальный A→B canary PASS→B Apply FAIL→verified safe rollback→C PASS, затем D из разрешённого источника пополняет резерв. Не требовать service PASS умершего A, но cleanup/readback обязательны. Unknown WAN/checker/cleanup не портит рейтинг всех узлов. Learning контекстный, ограниченный, не authority.

## 5. Исполняемый общий режим + исключения + DNS

Сохранить барьер NETWORK_POLICY_EXECUTOR_REQUIRED до настоящего совместного исполнителя. Не удалять его ради UI. На стенде доказать unknown domain, прямой IP, ноль overrides, узкий service scope → default для остальных, удаление override → default. Исключённые устройства и сайты не получают обходы/Smart DNS; российская классификация не зависит от выбора карточки.

Общий DNS, service DNS и базовый DNS исключённых клиентов согласованы с маршрутом в одной транзакции. Exact A/AAAA/CNAME/TTL + original SNI/Host + нужный executor. Существующие TCP/UDP sessions, кеши, свой DoH/ECH и shared CDN IP — реальные ограничения, не повод скрыто расширять DIRECT или блокировать шифрование. Unknown name идёт общим путём; unsupported класс имеет согласованный исход. UI/SSH/DHCP/ND/bootstrap сохраняются.

## 6. Надёжное обновление компонентов и приложения

Закончить persistent transaction: точные старый/новый пакет+hash, conffiles, dependencies, фазы и recovery-helper. Удерживать previous-working до подтверждённой активации новой **живой** цепочки. `installed`, `candidate_validated`, `running`, `activated` отдельно. Новая версия Sing-box как sidecar должна реально пройти TUN/data path, не только config check Xray/USQUE SOCKS-canary.

Все conflicting manual/API/automatic mutations должны уважать pending fence; read-only и scoped emergency repair остаются доступны. Типизировать ошибку precheck/service/cleanup, не блокировать навсегда безопасный отказ, но не продолжать после неизвестной очистки. Переход pending→known только через проверяемый readback. Window/Stop/SafeMode/consent пересматривать до каждой mutation. Окно может закрыться во время rollback: cleanup должен закончиться.

Installer receipt привязать к asset digest/generation, различать not_started/handoff_uncertain/installing/rolled_back_verified/installed_verified. Завершить поколения журналов и fault injection до/после write/rename/fsync/powerloss. Retention не удаляет pinned/in-use/rollback refs. Автовключение установки и новых trust scopes — только принятой миграцией.

## 7. Каталоги, feeds и сценарии сервисов

Подключить GeoAggregatorCacheStatus к реальному read-model/UI без сетевого запроса на каждый GET. Фоновую загрузку передать существующей очереди, не городить ещё один scheduler. Проверить restart+offline, stale30d, invalid schema, запись полного диска, два процесса/вкладки, источники 304/429/503, cancellation. Хранение индекса не подтверждает imported-list/LKG runtime: эти уровни отдельно.

NodeStore: 32 плохих +33-й хороший, cursor после reorder/restart, partial feed, active/reserve/manual/rollback refs при GC; source ranking контекстный. Публичный feed/генератор не получает ключи и не является обязательным bootstrap. Generic derivedProbeURL не равно media/voice PASS.

YouTube: страница/видео/CDN/QUIC. Discord: страница/медиа/UDP voice. Telegram: сайт/DC/IP/media. AI: авторизация/API/web отдельно; не считать любой403 доказательством страны. Игры: auth/launcher/session UDP отдельно. Российские сайты: direct-exclusion и ручное переопределение без попадания соседей на общем IP. Реальные аккаунтные тесты — только с согласия, без чтения личных данных.

## 8. NFQWS2, WARP/USQUE и дополнительные исполнители

NFQWS2: видимость outgoing/incoming/retransmission/offload; narrow reversible offload experiment, bounded strategy candidates, user lists/assets/version preserved. Не считать webcurl голосом и не копировать весь set из другой сети.

WARP: одна пригодная registration, локальные exports, endpoint≠account. Unknown POST сохраняется и не повторяется новой identity. Бюджет/consent до регистрации; никакого массового создания аккаунтов. H3/H2 endpoint identity отдельна. Не использовать весь Cloudflare CIDR как список одного сервиса.

USQUE/Mihomo MASQUE: документы показывают различия QUIC/H2/L4 и места DNS. L4 TCP-only не покрывает UDP-голос. Проверить server ECDSA identity vs WG Curve25519, SNI, certificate/pin, chosen transport. Native TUN сам не означает, что маршруты настроены. Поздний hook от старого process не гасит новый.

HEV: проверить пользу относительно sidecar на слабом роутере; ICMP local echo не egress proof. Session/buffer limits измерять, не копировать sample8500 MTU/глобальные sysctl. Mihomo/HEV не должны задерживать три приоритетных законченных одиночных пути.

## 9. Ресурсы, UI и длительная приёмка

MemFree fallback исправлен; общий adaptive budget всё ещё нужен: лимиты CPU/RAM/temporary processes/probes/FD, batch/cursor/slow deadlines с приоритетом Stop/recovery. Не превращать чужие load thresholds в норматив, не обрезать поддержку по названию архитектуры. GOMEMLIMIT после измерения всей цепочки.

Главная — default Internet+Autopilot, индивидуальные сервисы и исключения, реальные причины и возраст snapshots. Одно «Использовать» запускает серверный intent; не новые модальные окна на каждую фазу. Не перерендеривать редактируемые поля фоновым polling.

Native bench → AArch64+два физических клиента → MIPS/MIPSel →24/72h с закрытым браузером и управляемыми отказами. CPU/RSS всей цепочки, throughput/latency under load, FD/goroutines, flash writes, recovery/Stop/API latency, число ручных вмешательств. Все непройденные ступени остаются not_run.
