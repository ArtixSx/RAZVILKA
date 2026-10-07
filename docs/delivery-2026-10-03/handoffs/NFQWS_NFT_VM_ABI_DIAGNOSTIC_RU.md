# NFT VM: deterministic diagnostic закрытого Linux 4.9 ABI

QA-only checkpoint поверх `f05c6fee564e7ff3cc994bbf5d237bb7489383b5`: новый portable test и этот handoff. Production decoder/socket, native observation test, capability и policy не меняются. Тест использует существующие wire fixture builders и original `newBackendNFTDecoder` → `consume` → `finish`; второго decoder и copied production helpers нет.

## Подтверждённая граница

В nft95 ROOT наблюдал `kernel=7.0.0-34-generic request=GETGEN_A outcome=generic-unknown capability=ungranted` на integrated source `c7b97e91da3bf6c65c62275d3956e2c44395bf34`. Этот лог не содержит response shape. Existing socket exchange при decoder error возвращает nil/error и не передаёт failed datagram вызывающему коду.

Reproducer доказывает несовместимость текущего **намеренно закрытого Linux 4.9 parser** с двумя обычными upstream v7.0 message shapes. Это current-ABI refusal, не обнаруженный production defect. Он **не устанавливает причину конкретного пакета nft95**, не проверяет фактический vendor/Ubuntu kernel и не обосновывает blanket parser relaxation или NFT absence. Actual packet instrumenter в этот checkpoint не входит.

## Первичные источники и fixtures

| Fixture | Первичный источник | Проверка original decoder |
| --- | --- | --- |
| Linux 4.9 positive control: NEWGEN с одним GEN_ID, затем успешный ACK с flags=0 и exact request header | [v4.9 nf_tables_fill_gen_info](https://github.com/torvalds/linux/blob/v4.9/net/netfilter/nf_tables_api.c#L3617), [v4.9 netlink_ack](https://github.com/torvalds/linux/blob/v4.9/net/netlink/af_netlink.c#L2114) | Только после обоих messages `finish` успешен; decoded generation совпадает с synthetic fixture |
| v7.0 NEWGEN: GEN_ID + GEN_PROC_PID + GEN_PROC_NAME, flags=0, AF_UNSPEC/version0 и согласованный res_id | [v7.0 nf_tables_fill_gen_info](https://github.com/torvalds/linux/blob/v7.0/net/netfilter/nf_tables_api.c#L9021), [v7.0 nft_gen_attributes](https://github.com/torvalds/linux/blob/v7.0/include/uapi/linux/netfilter/nf_tables.h#L1583) | Original GEN attr whitelist max=1 отвергает attrs 2/3; `errBackendInventory`, failed=true, finish Unknown |
| v7.0 successful ACK: error=0, exact request header, NLM_F_CAPPED | [v7.0 netlink_ack](https://github.com/torvalds/linux/blob/v7.0/net/netlink/af_netlink.c#L2463), [v7.0 ACK flags](https://github.com/torvalds/linux/blob/v7.0/include/uapi/linux/netlink.h#L77) | После valid 4.9 GEN изолированно отвергается ACK flags=0x100; `errBackendInventory`, failed=true, finish Unknown |

В v7.0 success ACK получает CAPPED даже без enabled NETLINK_CAP_ACK: ветка с appended request payload выбирается только для ненулевой ошибки без CAP_ACK. Здесь нет EXT_ACK/TLV. У NEWGEN оба process attributes имеют правильные NLA lengths/alignment; PID и NUL-terminated name полностью synthetic. Header destination/sequence и остальные поля берутся из прежних fixture builders, не из live системы.

Обе modern fixtures остаются generic Unknown, а не typed negative `backendNFTKernelError`; последующие valid old GEN+ACK не могут восстановить sealed failed exchange. Positive decoder control также не выдаёт capability: нет inventory/namespace provider, table dump, receipt или authority path.

Вывод tests ограничен static source/shape/reason/outcome и всегда `capability=ungranted`. PID/name, raw frames, generation, port/sequence, boot/netns identifiers и raw errors не печатаются даже при assertion failure. Статические reason labels относятся только к известным synthetic fixture shapes, не добавляются в production telemetry и не приписываются nft95.

## Проверки и ROOT follow-up

Owner checks PASS: Windows amd64 `go test ./internal/dataplane -run '^TestBackendNFT' -count=1 -v` (0.080s, включая оба новых ABI tests и прежние NFT decoder tests); package vet на Windows amd64/Linux amd64/Linux arm64; full package Linux amd64/arm64 test cross-compile. Здесь не выполнялись NFT observation, Linux/native/race, VM/router/HIL или live netlink.

ROOT отдельно сообщил actual router nft95 на том же source `c7b97e9`: RC0, kernel `4.9-ndm-5`, GETGEN_A validated-negative-kernel-ACK code22, complete-gen-reads0/tablecount0, capability ungranted; stderr empty, temporary artifact removed. Arm binary SHA256 `045f0c9f9d56d0fbd3d968f4ca5dc8d44e1bacb55d4014898885438277841f65`. Это ROOT platform observation, не запуск NFQWS owner и не sole-negative provenance/absence proof. Текущий error-only Code22 diagnostic не выдаёт grant.

Новый ABI test зависит от existing `network_backend_inventory_nft_test.go` fixture builders; observation-only overlay из прошлого checkpoint по-прежнему исключает его вместе с остальными portable tests. Для запуска ABI fixtures нужен обычный package test view с обоими portable test files.

Решение о supported ABI, typed provider integration и будущем sole-negative-error/absence classifier остаётся за ROOT после отдельного evidence review. Strict Unknown и capability ungranted сохраняются.
