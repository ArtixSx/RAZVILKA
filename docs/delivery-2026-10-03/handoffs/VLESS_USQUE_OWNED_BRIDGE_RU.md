# USQUE owned producer consumer

`runCanaryAttempt` использует реальный `usquediag.ProbeOwnedUSQUE`. Mandatory review guard, полный sealed catalog predicate, exact argv/private `engine.json` и explicit selected endpoint проверяются **до Processes.Start**, поскольку child может подключиться при запуске. Отсутствующий/отменённый/revoked guard, predicate или pin дают zero Start и zero producer.

После Start owned producer получает actual ProcessSpec root/binary/listener, exact QUIC либо HTTP/2 endpoint, FreshProfile и selected full predicate validator. Callback оценивает immutable bounded sample внутри producer before/after window. Generic SOCKS/legacy trace повторно не вызываются; owned failure не downgrade. Challenge и UDP не объявляются без отдельного producer proof.

Typed Owned receipt, checkedAt/validUntil, endpoint, transport и semantic grades сохраняются напрямую через общий `CanaryEvidence`; timestamps не обновляются consumer. Успешный Stop обязателен до записи staged transport/evidence. QUIC→HTTP/2 fallback получает отдельный actual owned proof. Commit переносит сохранённую запись; историческая canary запись не становится current live receipt нового runtime.

Любая ошибка Stop помечается private cleanup error и сразу завершает весь Canary, даже если Running сообщает false; следующий transport не запускается. Regression проверяет ошибку первого Stop при both Running true/false и второй потенциально успешный attempt: остаются ровно один Start/producer/Stop и ноль staged transport/evidence.

Sealed DEFAULT cell запрашивает отдельную transport readiness: existing explicit owned WARP trace, без catalog ConfirmedRoutes для default. Service/override cells требуют FrozenProbeService и matching full predicate digest. Empty/ambiguous/current catalog lookup и DisplayName не заменяют immutable service ID/URL.

CORE должен установить действительную review authority также в обычном explicit USQUE Apply/worker и actual-start admission в ProcessController. Missing authority остаётся отказом. Genuine USQUE/WARP account live ledger остаётся UNVERIFIED, пока координатор не выполнит разрешённый live producer acceptance; локальные fixtures не утверждают реальный tunnel/ALPN/UDP.
