# Upstream: контракты внедрения D07/D08/D11 — 04.10.2026

Исследовательский checkpoint, база `ceeaab843647e98b137c598c309949c739ad80ab`, ветка `sol/research-20261004`. Только этот документ; production, зависимости, VERSION, VM, роутер и GitHub не изменены. Временные raw-исходники сохранены вне worktree в локальном Temp. Это чтение кода и проектные предложения, не runtime/HIL PASS.

Адресное продолжение после принятия `48b3ab0`: [RESEARCH_NFQWS_BUNDLE_RU.md](RESEARCH_NFQWS_BUNDLE_RU.md) предлагает отдельный managed payload без исполнения stock hooks. Stock IPK suppression blocker ниже сохраняется; он не запрещает file-only установку собственного runtime с честным provenance.

Разбор механизмов по отдельному запросу: [RESEARCH_Z2K_D2K_RU.md](RESEARCH_Z2K_D2K_RU.md) — что z2k получает от NFQWS2, его Lua/туннели/диагностика и сопоставление с собственным C engine и Telegram веткой d2k. Это исследование отдельных идей, не предложение импортировать проект целиком.

Конкретное продолжение D07/D08 по existing code: [RESEARCH_LAN_NATIVE_DESIGN_RU.md](RESEARCH_LAN_NATIVE_DESIGN_RU.md) — native отрицательный MAC gate перед owned paths, exact iif, bounded TCP flow-name frontend, baseline socket proof и небольшие carveouts владельцам. Это дизайн normal capabilities с проверяемыми границами, не runtime PASS.

Production verifier D03: [RESEARCH_XRAY_PRODUCTION_VERIFIER_RU.md](RESEARCH_XRAY_PRODUCTION_VERIFIER_RU.md) — actual router socket через owned TUN, bounded typed transit lease и раздельные router/LAN/application статусы; normal Apply без постоянного внешнего LAN-агента. Новый contract требует реализации и native acceptance, текущий nil gate не снят.

Аудит последних UI доказательств и официальный доменный TUN: [RESEARCH_UI_TUN_AUDIT_RU.md](RESEARCH_UI_TUN_AUDIT_RU.md) — D01 готов к закрытию по DoD, конкретный незакрытый per-engine progress D12, ARM64/hidden границы и minimal sing-box/Xray frontend без DNS-IP угадывания. Только исследование и предложение, без source/runtime правок.

Подготовка storage для managed NFQWS: [RESEARCH_ENTWARE_STORAGE_PREFLIGHT_RU.md](RESEARCH_ENTWARE_STORAGE_PREFLIGHT_RU.md) — почему /opt UID1001/0755 блокируется, официальный EXT/SMB/UBIFS контракт и bounded read-only диагностика для OPS. Single-inode UID preparation лишь после доказанных mount/share facts и отдельной авторизации; recursive chown/remount/guard exceptions не предлагаются.

Actual TCP capture→Go→node: [RESEARCH_LAN_TCP_CAPTURE_RU.md](RESEARCH_LAN_TCP_CAPTURE_RU.md) — сравнение stock sing-box1.14.2/Xray и минимального TUN stack API, конкретный tun2socks/core candidate с original tuple, single physical capture class, frozen per-node inbound и Stop/DNS/ABI границами. Source audit и implementation proposal; dependencies/runtime не менялись. Межчатовая отправка отклонена auto-review и требует прямого разрешения пользователя.

Прочитаны REMAINING_AND_AGENTS_RU.md, TASKS.json, COORDINATION_RU.md, SOL_HANDOFF_RU.md, RESEARCH_RU.md, VALIDATION_RU.md, CHANGES_RU.md, TEST_REPORT_RU.md. Перед новым углублением прочитан завершённый `delivery-review/.review-local/ROUTER_RESEARCH_RU.md`. Его три первоначальные находки здесь не выдаются за новое исследование. Ниже уточнены механизмы внедрения и контрпримеры. H00/IM, DNS min-TTL/cache, общий addition receipt и исправления NET modinfo/srcversion повторно не предлагаются.

Поиск выполнен web; поведение проверено чтением raw-файлов по полным Git SHA, полученным через GitHub API. Некоторые GitHub страницы через web open дали cache miss; соответствующие исходники успешно прочитаны через raw.githubusercontent.com по тому же SHA. README и поисковый wiki не использованы как доказательство выполнения hooks или маршрутизации.

## 1. OPS: NFQWS2 требует нового поддерживаемого suppression contract

### Что дополнительно установлено

Revision wrapper `077f9af6068cd3380527085ca351b503a2dcf926`:

- [packages.mk:80–86](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/packages.mk#L80) собирает S51nfqws2 конкатенацией `entware-start`, `common`, `entware-end`. [conffiles](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/common/ipk/conffiles) перечисляет config/lists, но не init. Поэтому предварительно изменённый init не является устойчивым выключателем после установки нового package payload.
- [entware-end:1–18](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/etc/init.d/entware-end#L1) запускает `--daemon`, затем firewall IPv4/IPv6 и system_config. Проверки ENABLED и подключения rc.func в собранном Entware пути нет. [common:12–38](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/etc/init.d/common#L12) читает shell config и определяет процесс через pgrep/PIDFILE/kill-0; это не exact kernel ownership RAZVILKA.
- [preinst:14–30](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/common/ipk/preinst#L14) при migration переименовывает старый config. Suppression внутри этого config потерялся бы именно в нужном crash window. [prerm:15–18](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/common/ipk/prerm#L15) также вызывает stop. Известный [postinst:106–122](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/common/ipk/postinst#L106) запускает start после package/config работы.

**Вывод:** существующий ENABLED=no guard для Sing-box нельзя переносить на этот package. Перечитанный `internal/components/singbox_init.go` защищает только конкретный template S99sing-box. Ни env-переменная без поддержки hook, ни редактирование старого S51, ни последующая остановка daemon не устраняют окно postinst side effects.

### Минимальный предлагаемый контракт

Предпочтение — suppression, а не передача живого daemon. Это **новая capability**, отсутствующая у прочитанной stock revision:

1. До opkg OPS проверяет полный old/new package lifecycle manifest: package digest, old/new init и maintainer-hook digests, версия suppression protocol. Включаются зависимости с hooks, rollback package и альтернативный OpenWrt init. Неизвестный hook — отказ до package effect.
2. В private durable каталоге вне package payload/config хранится `ManagedLifecycle{schema, component, transaction_id, old/new package digests, hook/init digests, phase, authority_epoch}`. Это структурированные данные, не shell source. Каталог и reader принадлежат RAZVILKA; regular files, ограниченный размер, отсутствие symlink, fsync файла и parent directory.
3. Проверенный пакет должен вызывать стабильный guard **до чтения config и любых lifecycle effects**. Managed mode подавляет package-owned start/restart/firewall/system_config и автоматический stop из prerm/postinst. Config migration, unpack и обязательные package проверки выполняются; RAZVILKA заранее останавливает только собственный runtime по exact receipt. Прямые firewall subcommands также защищены, не только case start.
4. Guard действует в старом и новом init/hook. Pending или повреждённая managed запись запрещает старт; отсутствие transient env после reboot не включает daemon. Состояние `managed-idle` остаётся после принятия: штатный rc.unslung не должен создавать второго owner на следующем boot. Удаление managed ownership — отдельная явная операция, не очистка временного файла в defer.
5. Command supervisor сохраняет прежний критерий wait4→ECHILD. Только после durable package outcome и независимой проверки payload/config RAZVILKA запускает свой exact binary/config либо принимает installed-idle. Отдельный live acceptance не выводится из exit0 opkg. Stop epoch перечитывается перед запуском и принятием.

**Реализуемость/ограничение.** На Netcraze достаточно файловой authority и поддерживаемого guard; PID/net namespaces, cgroup и children interface не требуются. Но stock package выше не имеет такой поддержки: это блокер автоматического managed update до поставки совместимого package. Допустим согласованный upstream hook или отдельно проверяемая managed сборка с собственным доверенным manifest/signature и явным provenance. Нельзя менять подписанный downloaded IPK на месте и продолжать считать его upstream package. Исследователь не создавал fork/package и не предлагает автоматически расширять доверие источников. Первый переход со stock old hooks также требует отдельного проверенного admission; наличие guard только в новом package недостаточно.

**Почему handoff пока хуже.** Receipt не меняет Linux parent/wait ownership. Краткоживущий supervisor не может передать adopted child произвольному уже работающему service supervisor одной записью PID. Понадобится реальное изменение топологии/долгоживущий owner, а также доказательство завершения всех остальных hooks. При наличии handed-off daemon ECHILD не наступил, значит нельзя публиковать прежний receipt «все потомки завершены». Name/PID exemption и пустой proc scan остаются запрещены.

**Приёмка OPS+координатор.** Настоящий opkg, отдельно package с поддержкой protocol: replace init, migration с rename config, double-fork daemon attempt, второй delayed writer; миграция выполнена ровно один раз, start/firewall counters равны нулю, delayed writer действительно дождались, ECHILD durable. Crash до/после guard receipt, после unpack и до postinst, затем reboot с очищенным env: init не стартует. Повторить upgrade и rollback; смена hook digest/foreign init — отказ до effect. Foreign daemon с тем же basename не получает signal. Stock NFQWS2 revision должна быть явно rejected, не falsely suppressed. Runtime launch после hooks отдельно проверяет Stop и installed executable identity.

Лицензия wrapper: [MIT](https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/LICENSE). Это не лицензия встроенного zapret2 binary/Lua; их лицензии и provenance потребуют отдельного manifest. Shell-код не копировался.

## 2. OPS/QA: offline opkg не изолирует жёсткие /opt hooks

**Проверенный источник:** Entware [opkg Makefile](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/system/opkg/Makefile) закрепляет source `80503d94e356476250adaf1f669ee955ec26de76`, compile-time lock `/opt/tmp/opkg.lock`. Прочитаны patches [500-paths](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/system/opkg/patches/500-paths.patch) и [520-root_dir](https://github.com/Entware/Entware/blob/969c703e6fd8b2ad84d82affaeb14b48d1fcb105/package/system/opkg/patches/520-root_dir.patch); это не полный аудит всех Entware patches. Последний использует /opt для проверки свободного места.

В upstream [pkg_run_script:1355–1417](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/pkg.c#L1355) offline root без force_postinstall пропускает maintainer scripts; с force они запускаются через `/bin/sh -c`, с PKG_ROOT, **без chroot**. NFQWS2 hooks выше PKG_ROOT не используют. `--noaction` — dry run, не штатная установка с подавлением только start. [opkg_install.c:1434–1496](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/libopkg/opkg_install.c#L1434) исполняет old prerm/new preinst до удаления старых файлов и установки новых scripts/data. Поэтому перехват одного нового postinst не покрывает переход.

**Практическое дополнение к стенду.** Не запускать оригинальный NFQWS2 hook на router/обычной VM root, полагаясь на offline-root. Координатору нужен отдельный disposable VM filesystem/изолированный корень с собственным `/opt`, package DB и lock; firewall effects дополнительно изолировать сетью либо проверенными recording fixtures. Не использовать VM network isolation как доказательство переносимости namespace supervision на Netcraze. Сохранить два уровня: настоящий opkg с root-aware synthetic hooks проверяет журнал; pinned NFQWS2 hooks в полном изолированном `/opt` проверяют конкретный suppression adapter. Второй нельзя подменять первым.

**Regression:** hook записывает sentinel в абсолютный `/opt` и в PKG_ROOT; проверяются обе области изоляции, host package DB/lock/init не изменены. Затем оригинальная последовательность init replacement+migration проходит под suppression. Лицензии: [upstream COPYING GPLv2](https://github.com/openwrt/opkg-lede/blob/80503d94e356476250adaf1f669ee955ec26de76/COPYING), Entware Makefile объявляет GPL-2.0, собственный SPDX Makefile — GPL-2.0-or-later. Код opkg в MIT RAZVILKA не копируется.

## 3. CORE/OPS: Stop authority вне old/new config, с отдельной точкой принятия

**Наш конкретный разрыв на базе.** `selfupdatejournal.allowedTarget` включает `etc/razvilka/config.json`; images/digests сохраняют точные old/new файлы. `config.CommitServiceRuntime` меняет `ServiceControl.Stopped`, applied services и revision в основном config. `durable_runtime_jobs.go` уже принимает Stop durably и отменяет работы, но исполнение берёт operation admission. Эти механизмы полезны и не заменяются вторым scheduler. Однако перечитывание Stop только из заменяемого config не даёт независимой authority для restore old/new images. На этой базе не установлено, что все installer/startup paths читают независимую Stop запись; чужой WIP не аудирован.

**Переносимый upstream принцип.** RAUC revision `1a412fe80badb9cf91f5374ea2ef791de4db55a9`: [reference.rst:178–210](https://github.com/rauc/rauc/blob/1a412fe80badb9cf91f5374ea2ef791de4db55a9/docs/reference.rst#L178) требует хранить central status/data вне обновляемого filesystem; [status_file.c:368–416](https://github.com/rauc/rauc/blob/1a412fe80badb9cf91f5374ea2ef791de4db55a9/src/status_file.c#L368) сохраняет статусы всех slots в central file. Это доказательство отделения metadata, **не** готовый Stop протокол и не доказательство fsync на USB: функция использует GLib save API, его durability здесь не проверялась. RAUC [COPYING](https://github.com/rauc/rauc/blob/1a412fe80badb9cf91f5374ea2ef791de4db55a9/COPYING) — LGPL-2.1; варианты лицензии отдельных файлов не устанавливались. RAUC/GLib/bootloader dependencies переносить не предлагается.

### Предложенный минимальный API

`ControlAuthority{schema, installation_id, epoch, stopped, safe_mode, stop_operation_id}` — фиксированный private файл вне self-update targets, backup/rollback image set и заменяемого init. Start/Resume и Stop имеют один короткий межпроцессный control lock, независимый от долгого update lock. Ядро API: `AcceptStop(expected_epoch, operation_id)`, `ReviewResume(config_revision, current_epoch)`, `AuthorizeEffect(expected_epoch, effect_id)`; имена проектные, файл назначает координатор CORE/OPS одному владельцу.

1. HTTP auth/CSRF и CAS остаются. Повтор Stop с тем же operation ID возвращает прежний epoch; новый Stop атомарно увеличивает epoch и пишет stopped=true. ACK «Stop принят» только после fsync+rename+fsync directory. ACK не утверждает, что вся сеть уже очищена. Failed durable write — нет accepted status.
2. После принятия Stop отменяется выполняющийся effect; owned cleanup присоединяется. HTTP не ждёт installer writer lock для записи intent. Полное завершение Stop публикуется только после exact cleanup/readback, без global flush/killall. UI/backend различают accepted, stopping, stopped, cleanup-unverified.
3. Повторное чтение перед effect само по себе имеет TOCTOU. Epoch validation и **admission начала** каждого эффекта сериализуются тем же коротким control lock с AcceptStop. Не держать его на протяжении opkg/USB write. Effect, допущенный до Stop, подлежит cancellation/join; effect, допущенный после Stop, запрещён. Нужны guard в реальном helper/startup, а не только проверка в HTTP controller.
4. File recovery может восстановить точные old/new bytes для целостности, сохраняя новый Stop. Оно не может стартовать runtime или удалить inhibition. Требуемые data-only recovery writes допускаются лишь отдельным matching recovery полномочием; Stop не является разрешением произвольно менять config. Frozen config не переписывается ради зеркала stopped=true; зеркало обновляется отдельно после settlement, основной digest fence сохраняется.
5. Init, worker, package guard, self-update helper, rollback/restart/live acceptance читают один authority record. Нет записи при первичной установке — только явный bootstrap с установленной ownership; corrupt/unknown schema после установки — fenced stopped. Новый runtime не принимает старый review epoch. Config со stopped=true также не позволяет старт: миграция никогда не очищает Stop автоматически.
6. Resume отдельно сохраняет stopped=false и новый epoch по свежему review, когда pending update/ownership permits. При этом ранее допущенные helper tickets не оживают. В rollback/downgrade manifest обязательна capability этой authority schema для **обоих** бинарников. Старый бинарник, который её не понимает, не допускается в автоматически активный runtime; один guarded init недостаточен, если старый HTTP Apply/worker затем обходит guard.

**Граница доступности:** отдельный intent устраняет зависимость от config replacement, но не создаёт HTTP server во время остановки самого приложения. При аппаратной приёмке отдельно проверять Stop на работающем management endpoint/helper; не обещать непрерывный HTTP через restart без отдельной реализации. Постоянный внешний ПК для authority/health не нужен.

**Meaningful regression:** barrier перед/после каждого rename config и перед admission restart; Stop ACK; crash helper/app; matching restore old/new; boot с одним образом; rollback/downgrade. Новый epoch и stopped=true сохраняются, ни одна launch после Stop admission не проходит. Проверить Stop во время занятого update lock, slow USB fsync, failed authority write, corrupt file, PID reuse и повтор HTTP. Detached child+delayed writer завершаются supervisor contract из раздела1. LKG остаётся; unknown opkg не replay. VM fault injection не объявлять physical power-cut PASS.

## 4. CORE/NET: общий executor с типизированным miss и backend capability matrix

### Дополнительное доказательство default поведения

Xray revision `b26a91de4f3294e26a0ad0a970b81a386a41f789`: [router.go:188–216](https://github.com/XTLS/Xray-core/blob/b26a91de4f3294e26a0ad0a970b81a386a41f789/app/router/router.go#L188) проверяет ordered rules; [dispatcher/default.go:434–485](https://github.com/XTLS/Xray-core/blob/b26a91de4f3294e26a0ad0a970b81a386a41f789/app/dispatcher/default.go#L434) при ошибке PickRoute выбирает default handler. Но matching rule с отсутствующим outbound **закрывает** link, не отправляет его в default. [RouteOnly:299–315](https://github.com/XTLS/Xray-core/blob/b26a91de4f3294e26a0ad0a970b81a386a41f789/app/dispatcher/default.go#L299) позволяет использовать sniffed имя для routing, сохраняя исходный target; FakeDNS выделен отдельно. [LICENSE](https://github.com/XTLS/Xray-core/blob/b26a91de4f3294e26a0ad0a970b81a386a41f789/LICENSE) — MPL-2.0. Это source behavior, не испытание наших profiles. Generic routing error upstream не следует превращать в наш typed NoMatch: compiler/adapter отдельно проверяют completeness и failure policy.

Перечитанный pbr [mark guard:1026–1028](https://github.com/openwrt/packages/blob/0774799a271fc22724fae6f7ee32f5df932cc08a/net/pbr/files/etc/init.d/pbr#L1026) прекращает дальнейшие pbr matches, сохраняя чужие mark bits; [mark setter:2321–2323](https://github.com/openwrt/packages/blob/0774799a271fc22724fae6f7ee32f5df932cc08a/net/pbr/files/etc/init.d/pbr#L2321) меняет только mask. Но [route creation:2340–2363](https://github.com/openwrt/packages/blob/0774799a271fc22724fae6f7ee32f5df932cc08a/net/pbr/files/etc/init.d/pbr#L2340) делает flush/replace таблицы. Брать принцип mask/ordered routing; продолжать использовать наш exact addition receipt вместо этих ownership предположений. [Makefile](https://github.com/openwrt/packages/blob/0774799a271fc22724fae6f7ee32f5df932cc08a/net/pbr/Makefile#L9) этой revision — AGPL-3.0-or-later, не старое wiki GPL-3.0. Код не копируется в MIT проект.

### Один контракт, не новый owner

CORE выпускает immutable `CompiledPolicy{generation, config_revision, control_epoch, scope, default_decision, ordered_site_exclusions, ordered_service_overrides, family_protocol_caps, bootstrap_pins}`. NET потребляет **тот же scope/generation** в DNS/WG/DPI, VLESS — в TUN/proxy. `scope` содержит selected ingress+LAN prefix bindings, guest opt-in и device exclusions; пустой selected ingress не означает any. IP/MAC binding не считается защитой от spoofing и требует наблюдаемого обновления lease/IPv6 address.

`Classify(source, ingress, destination, flow_metadata)` возвращает одно из `OutsideOwnedScope`, `ExplicitBaselineExclusion`, `Default`, `ServiceOverride`, `CapabilityRefused`, `ExecutionFailed`. Service miss не является DIRECT; ошибка исполнения совпавшего override не является miss. Для failure действует уже согласованный fallback/scoped block, не автоматическая WAN утечка. Добавления цепей/routes/sets — существующий общий addition receipt, не новый журнал.

| Новое соединение | Решение |
|---|---|
| Excluded device, guest без opt-in, WAN/control ingress | OutsideOwnedScope: нет owned DNS/NFQUEUE/TUN/mark |
| Selected client, установленное ручное site/IP exclusion | Baseline по явно заданной семантике исключения |
| Selected client, нет services / unknown name / IP-only flow | Default |
| Имя текущего flow совпало с override и source scope подходит | ServiceOverride |
| Override удалён, source mismatch, неподтверждённое IP→name | Default |
| Override совпал, outbound отсутствует/сломался | ExecutionFailed: согласованный fallback/block |
| IPv6 или UDP требуют отсутствующей capability | Отказ Apply для этой области либо заранее выбранный scoped block |

Ingress/device gate выполняется **до** DNS redirect и всех engine actions; исключение не реализуется одним RETURN в service ветке. Destination stage продолжает default после service miss. DNS TCP53 и UDP53 используют одинаковый scope; router-output/bootstrap имеют отдельное ограниченное полномочие, не LAN-wide default. Не менять чужие marks, forwarding и conntrack глобально. Existing flows удерживают exact generation/decision до заданного drain/cleanup; TTL expiry не вызывает массовый reset LAN.

**Существенное ограничение kernel-only backend:** mark/IP rules не умеют перевести отдельный flow из WG-default в WG-service по TLS имени после начала соединения. Не обещать поздний перенос уже начатого TCP. Для domain overrides нужен data path, который принимает поток до выбора outbound, либо проверенная FakeIP/другая различающая destination схема. VLESS owner и NET должны доказать конкретный мост domain classifier→WG outbound; наличие standalone WG adapter этого моста не доказывает. Default WG all-except по source/IP реализуется отдельной capability раньше domain-aware overrides.

**Сайт-исключение без видимого имени:** IP CIDR exclusion имеет честную IP-wide семантику. Domain exclusion на ECH/unknown UDP при shared IP нельзя гарантировать одним kernel IP set; capability/coverage показывается при review. Продуктовый scope не менять молча ради этого ограничения. FakeIP и proxy-all не включаются автоматически: нужна отдельно принятая архитектура и compatible DNS/TUN/recovery.

**Bootstrap/health:** CORE публикует DAG resolver endpoint→control WAN pin, tunnel endpoint→bootstrap DNS/pin, default/service DNS→выбранный проверенный outbound. Reject cycle до Apply, точные pins не становятся разрешением для LAN bypass. On-router bounded health проверяет actual outbound/UDP/IPv6 capabilities и owned readback, отдельно от LAN proof. Health без внешнего ПК реалистичен; local proxy probe не означает selected-client HIL. При недостаточной visibility статус inconclusive, LKG не заменяется.

**Приёмка:** selected/control/excluded/guest клиенты, неизвестный TLS host и literal IP, пустой override list, удаление override, source mismatch, absent matching outbound, TCP/UDP v4/v6, DNS TCP/UDP, endpoint/name change, browser closed, app reboot. Packet capture на клиенте и WAN+tunnel, exact rule/route counters, foreign marks/routes сохранены. NET kernel4.9 capabilities проверяются отдельно: fw4/ucode/nft-only рецепты OpenWrt не переносимы автоматически.

## 5. CORE/NET: DNS observations не дают имя flow; публикация и TTL связаны с ответом

Первоначальный handoff уже установил Sing-box reverse-map limit. Здесь уточняется **более сильный контрпример**: даже если в ledger только один qname→IP и conflict отсутствует, следующий IP-only flow может быть обращением напрямую к этому адресу. Он не обязан быть результатом DNS lookup. То же относится к неизвестному сайту с общим CDN IP и клиентскому DoH. Client+IP ключ уменьшает межклиентское загрязнение, но не решает идентификацию внутри клиента.

Источник: Sing-box revision `2ff3985c0a8fd628ab10b9ec9cd3d37512909c57`, [dns/router.go:1121–1133](https://github.com/SagerNet/sing-box/blob/2ff3985c0a8fd628ab10b9ec9cd3d37512909c57/dns/router.go#L1121), [route/route.go:590–609](https://github.com/SagerNet/sing-box/blob/2ff3985c0a8fd628ab10b9ec9cd3d37512909c57/route/route.go#L590). Reverse mapping хранит один RR owner на IP с TTL A/AAAA и может заполнить metadata.Domain. **Вывод из ключа/потребителя:** это эвристика, которую нельзя включать как authority для наших strict default/service rules. Реальная flow name metadata или отдельно проверенная FakeIP mapping имеют другую семантику. [LICENSE](https://github.com/SagerNet/sing-box/blob/2ff3985c0a8fd628ab10b9ec9cd3d37512909c57/LICENSE) — GPL-3.0-or-later; заимствования кода нет.

**Дополнительная граница sniffing:** [RFC9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1) и [RFC9114 §3.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3) допускают reuse одного HTTP/2 или HTTP/3 соединения для нескольких origins при выполнении проверки сертификата. Следовательно, одно TLS/QUIC имя не доказывает имя всех последующих зашифрованных requests. Это нормативный факт и вывод о flow-level классификации, не измерение браузера. В capability review указать granularity: connection-level override не обещает per-request изоляцию coalesced origins. FakeIP тоже требует проверки такого reuse, а не автоматического объявления решения. TLS не ослаблять и interception не вводить. RFC — текст IETF с copyright/Trust notice, код/фрагменты текста не заимствованы.

### Что сопрягать с existing DNS, а не писать заново

В базе `answer_details.go` уже даёт original answer chain/min TTL, `scoped_cache.go` — bounded client ledger; `scoped_query.go` проверяет provider guard и уменьшает wire TTL с DoH Age/local residence. `scoped_listener.go` отправляет reply после resolve. Но resolver обслуживает только exact client+domain choices и A/AAAA; неизвестный qname возвращает ErrScopedDNS. Это не готовый DNS-default для всего интернета. Перенаправить весь selected DNS в этот listener сейчас означало бы сломать unknown names/прочие типы запросов.

NET расширяет композицию, сохраняя строгий service resolver: `ServiceSelection{Match, NoMatch, Refused}`; NoMatch идёт в авторизованный default DNS path, Refused/changed-provider не становится direct fallback. Общий DNS path должен сохранять стандартные DNS types/EDNS/TCP semantics по явным capabilities; не снимать existing validation ради arbitrary packets. Excluded client не попадает в owned DNS даже если у него был старый binding/cache.

`DNSObservation{policy_generation, control_epoch, client_binding_revision, provider_identity, original_qname, qtype, aliases, addresses, observed_at, expires_at, observation_id}` использует existing ledger. Для same-IP observations сохраняется множество references и conflict/diagnostic state; никакого last-writer-wins route ownership. Окончание одной lease не удаляет адрес/reference другой; удаление override/provider/scope generation немедленно прекращает старую authority. Observation не создаёт IP-only service override автоматически, даже без conflict. Sniffed имя текущего flow может выбирать действующее domain правило независимо от DNS lease; endpoint address из DNS подчиняется своей expiry.

**Публикационный API там, где DNS reply действительно обещает новое data-plane mapping:** owner callback `PrepareAnswerBinding(observation, expected_generation, expected_epoch) -> receipt`, затем `VerifyReady(receipt)` и final guard до отправки wire. Это требуется, например, при принятой FakeIP mapping; в обычном name-sniff режиме domain rules публикуются вместе с policy generation, а observation остаётся диагностикой. Не добавлять бессмысленную IP route ради любого DNS answer.

Callback выполняется для fresh и cache-hit ответа; проверка cache не заменяет dataplane readback после restart. Ответ не выдаётся, если обещанная mapping не подготовлена: bounded SERVFAIL либо явно разрешённый default-response mode. Нет объявления override ready с first-flow race. TTL сокращается на время публикации и отправки; min CNAME/A/AAAA, DoH Age и наш cap остаются верхней границей. TTL0 не даёт reusable mapping; использовать default/явно отказать mapping mode, не продлевать искусственно. Rollback/Stop до send отменяет публикацию по exact receipt; успешная запись ledger сама по себе не route acceptance.

**Meaningful regression matrix:**

| Сценарий | Что должно быть доказано |
|---|---|
| Один client, service.example и unknown.example → один IP | unknown flow остаётся default; service flow только по своему имени |
| Один свежий service lookup, затем literal-IP TCP/UDP | Default даже при единственной неистёкшей observation |
| Два клиента/два providers → одинаковый IP | Нет переноса решения между bindings |
| CNAME TTL5, A TTL300, DoH Age3, публикация ещё1с | Lease/wire lifetime не больше оставшегося1с; после expiry новые DNS-derived mappings не используются |
| TTL0, delayed callback, callback failure | Нет искусственного reusable TTL; нет early successful answer обещанной mapping |
| Cache hit после удаления owned mapping/restart | VerifyReady не пропускается; восстановление либо bounded отказ |
| Provider/scope/Stop сменился между resolve и send | Старый answer/mapping не публикует прежнюю authority |
| Override удалён при активном flow | Новые flows default; старый — только документированный exact drain |
| ECH/QUIC fragmented/unknown UDP/клиентский DoH | Отсутствие имени не заменяется IP reverse-map authority |
| HTTP/2 или HTTP/3: два origins с совместимым сертификатом в одном connection | Зафиксирована connection-level granularity; нет ложного обещания отдельного пути каждому зашифрованному request |
| Неподдержанный DNS type в общем default listener | Честная capability/default DNS semantics, не случайный Refused всем интернетом |

Времена проверять injected clock+barriers в unit, затем двумя именами одного настоящего test server IP и packet capture в native VM. Ни один synthetic API ответ не является LAN acceptance. Ресурсы ограничить existing cache/queue budget и измерить на ARM64; external PC нужен только для независимого HIL, не постоянного production health.

## Передача владельцам и граница checkpoint

| Владелец | Первый конкретный результат |
|---|---|
| OPS | Capability preflight old/new hooks; reviewed managed-lifecycle suppression protocol; stock NFQWS2 отказ до effect |
| CORE + OPS | Независимый durable ControlAuthority с linearized Stop/admission и совместимостью rollback binaries |
| CORE | CompiledPolicy и typed NoMatch/ExecutionFailed, capabilities/порядок exclusions→overrides→default |
| NET | Default DNS composition и pre-send binding callback поверх existing resolver/cache; kernel capability proof |
| VLESS + NET | Подтверждённый domain-flow dispatch→WG/proxy bridge; не IPset attribution по одному DNS answer |
| Координатор | Разрешённая схема package trust; isolated /opt hook стенд; native/HIL acceptance и общий gate |

NFQWS2 circular, AWG module formatting/multicall и WARP enrollment/feed темы этой порцией не повторены. Passwall/OpenClash/HomeProxy остаются следующими адресными источниками для проверки конкретного backend, а не установленными вторыми managers. `NETWORK_POLICY_EXECUTOR_REQUIRED` сохраняется до полноценного общего executor и DNS capabilities.

Проверка этой порции: `git diff --check`; просмотр только нового документа и diff scope. Runtime/tests не запускались, потому что production изменения отсутствуют и live окна принадлежат координатору. Этот checkpoint не закрывает D07/D08/D11 и не является основанием production установки.
