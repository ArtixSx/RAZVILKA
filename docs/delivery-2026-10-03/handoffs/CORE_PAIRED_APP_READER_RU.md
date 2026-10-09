# Adapter-bound paired reader обычного App

Родитель: `355381ea595e6557893e53465d104cf298004a8a`. Зависимость — OPS `OpenFileJournal`/paired4, уже входящие в исходный Root `10acec04`; никакие остальные WIP OPS не включены.

`SelfUpdateFiles.Current` и `Action` открывают journal через существующий actual adapter `OpenFileJournal`, если он установлен trusted production constructor. `configuredSelfUpdateFiles` устанавливает этот provider только при совпадении всех фиксированных deployment roots. Ошибка provider не вызывает fallback. Legacy construction сохраняет обычный reader.

`Store.Current` читает формат и metadata. Поэтому для paired4 App дополнительно вызывает `RetainedReceipt` через тот же Store с конечным read-only context, проверяя retained images и исходный paired archive/helper reader, затем перечитывает Current и сравнивает весь receipt. Bare Store не получает paired evidence. Это не effect admission или runtime proof.

Action `install` допускает исходный `paired-prepared` checkpoint только с точными завершёнными тремя pre-file commands. Настоящий `InstallAdmitted` и каждый исходный effect callback остаются обязательными; прочие командные/rollback переходы не расширены.

Windows: все `^TestSelfUpdate` 12.107s; focused App order/HTTP/paired tests 2.673s; Windows и Linux arm64 App vet. Модели используют actual App и защищённый journal, paired publication и six-file installation. Archive/process evidence явно моделируется; provider/evidence refusal и изменение closing pointer не допускают replacement или fallback.

Native migration/health не запускались. Offline requires-review остаётся pending; completed-live retirement требует отдельного настоящего App owner и доказанного завершения helper. Этот пакет не выдаёт retirement.
