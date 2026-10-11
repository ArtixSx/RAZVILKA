# NET D06 — runtime admission и native AWG3.1 fixture

Base: `e58bc32f99e7fddb3bfba75a459da7256e0df24d`, ветка `sol/net-20261003`. Только NET-owned файлы. Общие manager/policy/journal/app не изменены; VM, роутер, modules, namespaces и shared ports из NET не запускались. Production go.mod/go.sum/VERSION сохранены.

## Выполнено

`awgprofile.Detect/DetectTool` теперь снимают bounded read-only runtime receipt:

- Exact resolved executable path + SHA256 ограниченного regular file; идентичность строки `amneziawg-tools v...`; hash до/после version/module inspection.
- Loaded module `/sys/module/amneziawg/{version,srcversion,initstate,taint}`, kernel release и numeric kernel taint.
- Только read-only `modinfo amneziawg`: name/version/srcversion/vermagic. Version и srcversion на диске обязаны совпасть с загруженными, initstate — live, vermagic release — с текущим kernel. Новый `.ko` на диске не подтверждает старый loaded module.
- Повторная loaded inventory в конце; изменившиеся/неполные/неоднозначные/oversized данные не дают readiness. Общий command deadline7s, каждый command3s, output4096 bytes, tool hash max64MiB. Никакого module load/unload/reboot/install.
- Forced load/unload kernel taint bits2/8 или module F/R отвергаются. Out-of-tree O и unsigned E сами по себе не равны несовместимому ABI. Missing modinfo/srcversion/ABI и userspace backend остаются unknown/unsupported.

Новый `CheckRuntime` проверяет исходные факты для **всех** AWG profiles, а не доверяет SupportsAWG31/CompatibilityVerified boolean. Existing `Check` сохранён как version-only preview API для совместимости с CORE; он **не является новым runtime admission**. SupportsAWG31 и CompatibilityVerified из штатного Detect вычисляются только из строгой проверки. HardwareVerified остаётся false.

Адаптер использует CheckRuntime + VerifyTool (повторный resolved path/hash) в Validate, Canary до candidate файлов/мутаций и каждом native start. Activate перепроверяет до удаления previous policy/остановки старого runtime; Reconcile — перед recovery mutation после failed health. AWG всех версий идёт только через native `type amneziawg` + checked CLI, без старого unchecked quick path. Stop удаляет собственный native interface и не требует новой совместимости запуска.

Проверка метаданных и обычной loaded-module связи с kernel не гарантирует протокольную совместимость всех серверов. Для неё нужен реальный service/handshake на конкретном reviewed peer. Readback showconf/dump/private-key/PSK/header-protection-key не добавлен.

## Стенды

`TestAWGNativeCompatibilityReceipt` — opt-in read-only Linux test фактически загруженного AWG3.1. Missing/old/wrong/unknown module даёт FAIL при явно запрошенной проверке, установка или skip вместо acceptance не выполняются. Искажённые receipts тестируются как копии данных; несовместимый `.ko` действительно не загружается.

`TestAWG31NativeCandidateIsolation` использует реальный kernel AWG3.1 + CLI, два independently keyed servers и client в owned Linux namespaces. На обеих сторонах одинаковые S1–S4, H1–H4, HeaderProtectionKey, RandomTrailers/DisableCookies. TCP/UDP IPv4/IPv6 payload, same-key отказ до второй Noise session, positive candidate, wrong-peer rejection, live-after после каждой ветви, чужой host route и temporary cleanup. Никакого userspace fallback. AWG preflight идёт до первой namespace mutation. Harness переиспользует accepted D04 logic; WG режим сохраняет свои backend/table/priority.

CLI output при native setconf failure не выводится, чтобы диагностика ошибочного параметра не раскрыла secret line. При failed child снимается только публичный WG/AWG readback.

Воспроизводимые official pins, prerequisite, build/load и оба native запуска: [NET_D06_PREREQUISITES_RU.md](NET_D06_PREREQUISITES_RU.md). CLI `v3.1.20260812`/`ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`; kmod `v3.1.20260906`/`4569c4c67f3a57414969260cafbbd04694fbaae0`. Сборка для VM kernel7.0.0-34 пока unverified; Netcraze4.9-ndm-5 arm64 без netns требует отдельного firmware/module/HIL plan.

## Локальная проверка

Go1.26.5, GOMAXPROCS2, GOFLAGS-p=2:

- Full `go test ./internal/awgprofile ./internal/dataplane -count=1`: RC0, dataplane49.173s.
- После последних refinements `go test ./internal/awgprofile ./internal/dataplane -run 'AWG|Amnezia|WGEndpoint|WGCanary' -count=1`: RC0.
- Windows и Linux/amd64 `go vet ./internal/awgprofile ./internal/dataplane`: RC0.
- Linux/amd64 CGO_ENABLED0 `go test -c` обоих пакетов: RC0; outputs только TEMP и удалены.
- gofmt / git diff --check: RC0. Race не выполнялся в этом checkpoint.

Native AWG3.1, router HIL/soak, missing/wrong module на аппаратном устройстве здесь **не выполнены**. D06 целиком не закрыт. Независимый прежний D05 native-wg-08 RC0 подтверждает оба семейства в Linux VM, не HIL; после расширения общего native helper координатору нужен адресный WG D04/D05 regression вместе с AWG test.

## CORE/VLESS wiring и оставшиеся ограничения

Актуальное состояние на 11.10.2026: [WG и AWG prerequisites для подключения App](NET_WG_AWG_PREREQUISITE_AUDIT_20261011_RU.md).

1. CORE: четыре App blocker/canary вызова по-прежнему используют version-only `Check`. Воспроизводимый fixture получает ноль blockers при трёх отказах `CheckRuntime`. Требуется raw-facts admission; хранение unsupported draft допустимо. Настоящий adapter уже отказывает до эффектов.
2. WG receipt wiring выполнен в `334a62ad`, restoration/publication recovery — в `ef2d7b5a`. Текущий Manager late EEXIST, unknown result, pre-admission Rollback и retained generation regressions проходят. Staged intent больше не является fallback cleanup authority. [NET_POLICY_RECEIPT_CONTRACT_RU.md](NET_POLICY_RECEIPT_CONTRACT_RU.md) сохраняет исходный исторический контракт.
3. Реальные WG App source и operation binding пока не имеют production callers. Native network fixture с LAN default routes не подтверждает контракт активного списка, приоритет исключений или обычный App lifecycle. Подключение принадлежит CORE; native/router acceptance — Root.
4. D08 получил отдельный synthetic baseline issuer `9bd6d7fc`, но production domain process factory, consumer и Commit retainer ещё требуются. Literal Xray resource не разрешает domain SOCKS mode; точный контракт передан VLESS и CORE.
