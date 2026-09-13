> Уточнение DC1 review: файл `VALIDATION_AWG31_WARP_RU.md` отсутствовал в переданном полном архиве. Не восстанавливайте его результаты по предположениям; текущие проверки и ограничения — в [DC1_REVIEW_2026-09-13_RU.md](DC1_REVIEW_2026-09-13_RU.md).

# Codex: продолжение единого кандидата AWG31-WARP

## Вход

Использовать полный SOURCE.zip или `.git.bundle` этого комплекта, не один HTML и не малый старый R5_DELIVERY. База — целый R5 `18fa5268f93069377f70e1f482820d1099d88856`; текущие HEAD/sha256 находятся в отчёте поставки. Не применять патч от R5 к rc.2. Перед любым переносом на main — diff/dirty audit, не стирать изменения пользователя. Читать AGENTS.md, если он появился. VERSION=0.18.2-dev, штатный toolchain Go1.26.5.

Сначала прочитать `AWG31_WARP_IMPLEMENTATION_RU.md`, фактическую `VALIDATION_AWG31_WARP_RU.md`, пользовательский master-plan §§4,53,55 и прежние handoff только в части действительно незакрытых задач. Старые утверждения об отсутствии компилятора или необходимости восстановить NodeStore не исполнять повторно.

## Не потерять

- Главная — мониторинг, Сервисы — сетка; AI только категория и отдельные service proof.
- Один scheduler, operation gate, ownership и transaction manager; ничего не запускать через скрытый AWG Manager/HydraRoute/z2k.
- AWGProfile parser, запрет hooks, redaction, CAS импорт, подстановка `on/off`, module+CLI gate, type=amneziawg, pinned endpoint.
- Для собственного AWG отсутствие `warp=on` нормально; для WARP соответствующий trace остаётся обязательным.
- Old-key canary до re-registration; явный AllowAccountRefresh, квота до POST, uncertainty checkpoint; Safe Mode проверяется ДО remote side effect.
- Ни модель, ни экран, ни наличие `.ko` на диске не означают реальный рабочий маршрут.
- Все foreign ресурсы только inspect до согласованной передачи управления. Никогда не rmmod при чужих/живых интерфейсах.

## Очередь работ: сначала вертикальная проверка, не новый сайт

### A0. Повторить программную приёмку

Зафиксировать source/hash и tools. `go mod verify`, `sh scripts/check.sh`, новые API/unit tests, `validation/native_http_smoke.py`, браузерные наборы. Учесть, что стандартный check не запускает Python/Playwright: их запустить отдельно. Новый Go HTTP + реальный браузер на собственном стенде: здесь HTTP проверен requests, прямую browser navigation отклонила политика среды. Не обходить администраторские ограничения.

Проверить import/preview/canary/health-policy, auth/CSRF/CAS, повторный запрос и конкурентный экспертный save. Ожидаемый профиль не должен меняться между preview и Stage/Canary. Нужна также ревизия сервиса/WAN непосредственно перед canary и перед Apply, сценарии cancel/manual override; укреплять existing review guard, не второй apply.

### A1. Полная проверяемая поставка AWG3.1-компонентов — сейчас отсутствует

Создать собственный ComponentManifest из закреплённых исходников tools/module и лицензий. Не копировать .ko только по имени arch или версии Entware. Определять model, SoC, ядро, ABI/vermagic и текущий owner; проверять криптографическое происхождение и совместимость. Сопоставить патчи Keenetic из AWG Manager с актуальным upstream, не выдавая документацию автора за собственный HIL. Код менеджера MIT, остальные компоненты — отдельные лицензии.

Первый целевой runtime — kernel `amneziawg` + CLI `awg`. Advanced gate должен сравнивать фактически исполняемую CLI с обнаруженной, а не разные пути при нескольких установках. Диск/загруженный модуль показывать отдельно. Kernel upgrade при живых интерфейсах отложить. Reboot требует заранее отдельного разрешения/окна; автопроверка не даёт права перезагрузить сеть.

DoD: чистая установка компонента на поддержанном test-router без AWG Manager/HydraRoute; wrong-model/ABI/hash/signature отказываются ДО запуска. Cold boot с незагруженным модулем: нормальный переход install→load→readback→canary, без обхода gate. Power loss/badmodule fallback протестирован; обычный rollback файлов не объявлять защитой от kernel panic.

### A2. Реальная изолированная и прикладная проверка

Два собственных тестовых AWG3.1 peers/профиля, выбранный сервис и отдельный контрольный клиент. Импорт именно оригинального .conf из Amnezia. Validate, module readback, temporary interface, handshake, egress и сервис; затем existing Apply. Проверить не только web, но объявленные протоколы отдельно.

Особенно проверить существующий `WARPWireGuardAdapter.healthState`: default health URL path унаследован от R5, а device-scoped routes пропускают часть проб. Нужно доказательство exact active interface/mark/source для post-commit и LAN без прямого fallback; pre-canary не заменяет этот тест. Не расширять источник до LAN=all ради прохождения теста. При недостаточной наблюдаемости вернуть partial/unknown.

Текущий source-bound canary — IPv4. IPv6-only, dual-stack/UDP/media должны получить самостоятельную реализацию и отрицательные контроли. Не менять глобальный IPv6 автоматически. Bootstrap endpoint/DNS не должен рекурсивно уходить в свой туннель. WAN/CNAME обновление endpoint при следующем Stage не заменяет постоянный TTL-aware supervisor: реализовать явный bounded refresh.

### A3. WARP: сквозное восстановление, не только модель квоты

Новые unit tests проверяют policy/квоту/pending/restart/Safe Mode. Но полная цепочка `processWarpHealth` с настоящими компонентами не имеет HIL. На стенде показать:

1. Один сайт отказал, другой через WARP работает: аккаунт не меняется.
2. Runtime завис, old-key isolated canary удачен: repair без регистрации; service scope не расширен.
3. Один порт недоступен: используем подтверждённый запасной порт прежнего peer.
4. Pure transport exhaustion + independent control + consent: одна кандидатная регистрация, лимит записан до POST.
5. POST timeout: pending checkpoint, не повторять вслепую; crash/restart не обнуляет квоту.
6. TLS/API/DNS/общий WAN/cleanup fault: не трактуется как разрешение на регистрацию.
7. Новый профиль не проходит canary: старый рабочий и rollback сохранены; неизвестный исход не называется успехом.
8. Между canary/generate/apply пользователь меняет политику, профиль, сервис или WAN: старое право отозвано.
9. Если healthy old path уже работает, новая запись источника или меньше ping не запускают замену.

Не считать необходимость нового Cloudflare устройства доказанной одним неудачным UDP-handshake; текущая ветка — разрешённая ограниченная попытка после транспортных и контрольных проверок. Добавить более точные failure classes и независимые UDP/control hints без массового сканирования. Общие лимиты аккаунтов соблюдать, не пытаться обходить rate limit.

### A4. Завершить restart/fairness/наблюдение

Квота сохранена, но измерить общий эксклюзивный legacy-routes round и нагрузку с интервалом 60с. Длинная canary/registration не должна блокировать аварийную отмену/восстановление другого сервиса. Сохранить один owner, по необходимости этапы split prepare/activate с lease.

Облегчить мониторинг активного туннеля; не запускать по процессу на сервис. Разделить error чтения health-file и policy-disabled. Проверить часы назад/вперёд/UTC, повреждённый журнал, duplicate events и bounded history. Generation after reload/negative later proof не восстанавливается как свежая из старого status.

### A5. Расширения после одного доказанного пути

Несколько AWG-профилей/peers с references/secret store, rename/delete защита, per-service reserves; собственные backend NativeWG+awg_proxy и amnezia-box только после per-field capability matrix. Не обещать все параметры AWG3.1 по поддержке двух флагов. Server-side rotation требует отдельного управляемого VPS API/SSH consent/host-key pin и синхронного обновления peer; нынешняя local client generation этого не делает.

Не добавлять публичный WARP-generator API ради автогенерации. Для альтернативной выдачи .conf/QR — локальный exporter, own keys, exact compatibility fixtures. WARP AWG camouflage-профиль не должен включать server-dependent HP/RandomTrailers без совместимого peer.

### A6. Обновления и выпуск

Довести отдельное общее направление signed compatible nightly install/install-on-demand. Этот кандидат не включает автоматическую установку приложения/всех движков. Не разрешать opkg upgrade как shortcut. Полный rollback binary/config/schema/dependencies, external helper, quarantine плохого выпуска и работа без сайта/генератора обязательны.

## Непрерывный HIL: минимум 24–72 часа

Выделенный Keenetic/Netcraze с snapshot, сначала одна модель/firmware. Два сервиса + независимый контрольный клиент, браузер закрыт. WAN loss/restore, DHCP-renew, NDM firewall regeneration, reboot, process kill, file-write interruption, OOM-pressure, нет места. MIPS/MIPSel и ARM64 отдельно. Collect RSS/CPU/FD/goroutines/temp/flash writes, ложные переключения, время восстановления, ручные действия; секреты не в отчётах.

Проверить coexistence с прошивочным WG/IPsec и неизменность baseline NFQWS2/YouTube. Отказ inventory не равен нулю интерфейсов/rules. Удаление сервиса не удаляет shared tunnel другого сервиса.

## Финальный отчёт каждой итерации

Указать base/head/source manifest, exact commands/exit codes, fresh build hashes. Раздельно: implemented, unit/integration-with-mocks, actual HTTP, actual browser+HTTP, cross-build, hardware, release. Непройденное/заблокированное не переносить в PASS и не переименовывать предыдущий архив.

## Стартовый запрос

Работай с полным кандидатом AWG31-WARP. Не начинай с нового UI. Прочитай этот handoff, implementation report и фактическую validation. Сначала повтори A0, затем подготовь один вертикальный A1/A2 на согласованном тестовом роутере. Если аппаратного доступа нет, продолжай programmatic/fault tests и поставку компонентов без их загрузки на рабочий роутер; подготовь HIL steps и needs-hil. Политику auth/TLS/owner/consent не ослабляй ради PASS. Все изменения небольшими отдельными commit, файлы/бинарники/отчёты сохраняй после каждого зелёного этапа.
