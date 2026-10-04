# CLOUD → VLESS/CORE: semantic service proof на owned USQUE

04.10.2026. Эта порция исправляет false service PASS от одного verified-TLS2xx. Required base: producer `2b23a613`, DNS boundary `a0b8cec`, actual Transport deadline fix `a5d168be84c813e3c7c5146ca4f1971d5b3d8827`. SHA этой порции передаётся root вместе с результатами проверки. Production thin hook и root acceptance остаются у VLESS/CORE/root.

Root сообщил независимое принятие semantic checkpoint `34074f56bf8d92ac96b1862bd1bda1ecd613a38c` без замечаний. Следующий actual Transport повтор выполняется root на combined source; full frozen predicate caller/thin hook пока делает VLESS. Это принятие библиотеки, не genuine USQUE/live acceptance.

## Согласованный API

```go
type OwnedServiceProbe struct {
    ID, URL string
    Challenge bool
    Validator func(OwnedServiceResponse) error
}

type OwnedServiceResponse struct {
    URL string
    HTTPStatus int
    ContentType string
    Body string
    BodyTruncated bool
}
```

Validator — trusted in-process callback из reviewed intent. Он принимает immutable bounded response после verified TLS, до повторного owned runtime capture и authority check. VLESS связывает closure с exact catalog ServiceID/ProbeURL и **полным frozen catalog.Service/selected catalog.Probe predicate**, затем вызывает existing `probecheck.Evaluate(service, selectedProbe, observation)`. Принять можно только `evidence.VerdictPass`. Реконструированный Service из одних ID/URL теряет BodyContains/JSON/schema/contenttype/status и не допускается; RoutePlanFor с одними ID/URL недостаточен. CORE должен передать frozen predicate в reviewed intent либо trusted sealed catalog provider. Ни HTTP/UI/receipt, ни display name/trim, catalog guess или alternative URL не создают validator authority. Reverse dependency CLOUD→dataplane отсутствует.

Response.URL — исходный exact approved URL. Redirect/proxy запрещены; HTTPStatus и ContentType берутся из фактического ответа. Для ordinary service Body содержит immutable sample≤32KiB, плюс один byte lookahead определяет BodyTruncated. JSON truncated должен отвергаться существующим semantic predicate; bounded nonJSON sample оценивается тем же predicate. WARP trace и nonce challenge сохраняют отдельные строгие full-body limits. Body, status и headers не сохраняются в receipt: сохраняется результат trusted validator внутри identity bracket.

Callback не выполняет dial, resolver или второй service request. Ошибка validator даёт фиксированный `owned-network-service-invalid`, без сырого body/error и без нового successful Owned receipt/selection. После callback producer повторно проверяет context, runtime identity и authority. Revoked guard/Stop/WAN/session/process drift не даёт semantic acceptance; timestamp берётся после этих проверок и не обновляется при readback.

## Три отдельные степени

- `ReachableRoutes`: approved service получил verified-TLS2xx; это факт reachability.
- `ChallengeRoutes`: отдельно вернулся exact fresh nonce response; это challenge, не semantic service predicate.
- `ConfirmedRoutes`: trusted Validator принял фактический ответ по строгому catalog predicate. Без validator TLS2xx/challenge сюда не попадают.

Typed owned receipt имеет `service_proof_version=1`. Каждый grade — unique safe ServiceIDs≤8, Confirmed/Challenge являются subsets Reachable. Producer сверяет все returned IDs/grades с отдельно captured requested services и их validator/challenge flags; списки клонируются независимо от probe call. Старый typed bodyless receipt без version не получает current grade. Flat BindingID/ConfirmedRoutes очищаются при наличии typed поля, включая null/duplicate/case-alias envelope, чтобы malformed/old/stale owned image не откатился к legacy green; semantic flat routes публикуются только после fresh current owned validation.

Doctor показывает reachability и challenge отдельно; `service-evidence=pass` требует fresh owned semantic ConfirmedRoutes. BindingID не является подписью proof fields: запись остаётся producer-owned, import/UI не получает сетевую или apply authority.

## Проверки и owner шаг

Meaningful portable regressions используют actual `probecheck` для YouTube generate_204: HTTP200 blockpage отвергнут, HTTP204 принят; отдельно full frozen BodyContains missing/exact, JSON schema missing/exact/truncation/content type, bounded large nonJSON, nil validator, nonce-only и callback error. Проверены zero evidence при semantic failure, identity/admission/cancellation drift вокруг callback, сохранение timestamps, exact requested IDs/URL и отказ старого/conflicting flat receipt. Independent static review не нашёл оставшихся production defects. Финальные unit/vet/compile-only app/dataplane и Linux amd64/arm64 test cross-compilation — RC0; exact результаты в [CLOUD_RU.md](CLOUD_RU.md). Сокеты/USQUE/root tests из CLOUD не запускались.

VLESS подключает только finished SHA после root review: внутри existing owned canary lifetime передаёт exact approved probes+validator, сохраняет весь typed receipt и возвращает semantic failure без legacy re-probe вне owned identity bracket. CORE сохраняет текущий worker/review guard и local-only readback; stale/history не выдаёт apply permission. Native Transport regression и actual USQUE H2/QUIC/WARP/UDP/service ledger остаются root окнами: [deadline regression](CLOUD_OWNED_DIAL_HARNESS_RU.md), [live checklist](CLOUD_USQUE_LIVE_CHECKLIST_RU.md).
