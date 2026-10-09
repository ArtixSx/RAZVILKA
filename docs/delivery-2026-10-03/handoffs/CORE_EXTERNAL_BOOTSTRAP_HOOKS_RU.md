# Общие Main/worker hooks для external old193 bootstrap

Родитель: `10acec04f921d044c11e369396873a84fdd0a62d`.
Producer/API: законченный OPS `bc935a35031b890be5e49f618a1fefa69f65a175`, уже интегрированный в родителя как `7876d8ba`. Другие незавершённые изменения OPS не нужны.

Обычный Main вызывает существующий `runExternalBootstrapCommand(args, productionSelfUpdateJournalRoots())` до остальных command dispatch и bootstrap. Фиксированная команда, исходные production roots и закрытый разбор аргументов остаются у OPS producer.

Глобальный worker `selfUpdateEffectAdmission` допускает action `bootstrap-offline` через исходный `WithSelfUpdateEffectAdmission`, только пока durable control UNSTOPPED и совпадают installation ID/sequence. SafeMode старой конфигурации не заменяет durable Stop. При durable Stop bootstrap возвращает `ErrSelfUpdateStopped` до чтения конфигурации; stopped compensation не выдаёт ему допуск.

Приватный `selfUpdateEffectAdmissionAt` выделен для тестов исходного защищённого control journal. Production wrapper всегда передаёт фиксированные `/opt` roots; HTTP/CLI не получает новых полей, root overrides или флагов допуска.

Проверки: Windows focused command tests 1.331s; Windows и Linux arm64 `go vet ./cmd/razvilka`. Leaf tests используют настоящий защищённый control journal и явный effect callback; проверяют changed installation/epoch/action, cancellation, неизменность файлов, durable Stop и ранний Main dispatch с отказом от тестовых roots.

Этот пакет не доказывает native old193 migration. До её запуска остаются общие CORE hooks строгого original installer-role scanner и adapter-bound paired App Current/Action/retirement. Source harness и фактический Linux run принадлежат Root.
