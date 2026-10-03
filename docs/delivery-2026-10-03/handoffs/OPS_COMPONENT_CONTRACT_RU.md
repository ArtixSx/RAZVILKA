# D11 component supervision: реализованный контракт OPS → CORE

Обновление 03.10.2026, база `99ac304`, IPK fixture отдельно исправлена в `9bdf305`.

**Baseline Netcraze 4.9 имеет только mnt namespace; PID namespace/cgroup/unshare не являются обязательной зависимостью.** Реализация OPS использует отдельный долгоживущий process `component-package-supervisor`, включающий PR_SET_CHILD_SUBREAPER. Процесс пакета получает свой process group; detached/double-fork/setsid ребёнок остаётся дочерним/adopted процессом subreaper. Только kernel wait/reap всех детей до ECHILD позволяет записать durable reaped receipt. Пустой /proc scan не доказательство. Смерть supervisor в том же boot без такого receipt оставляет unknown fenced; подтверждённый новый boot доказывает отсутствие прежних процессов, но не успех команды. Namespace пока не реализуется даже как accelerator.

Фиксируем вызовы для main (при согласовании CORE):

```go
// Linux-only, фиксированный production state root, opkg/argv из matching
// private command record. Никаких path/PID/command/argv из HTTP.
components.RunPackageSupervisor(transactionID, component, action string) int
// action: только "upgrade" или "rollback".
// CLI: razvilka component-package-supervisor <transactionID> <component> <action>

// Отдельный короткий CLI process. PR_SET/GET только для самого probe process,
// без дочерних процессов, файлов, пакетов/сети/изменения сервисов.
components.ProbePackageSupervision() error
// CLI: razvilka component-package-supervision-probe

// Read-only, можно вызывать из recovery guard под другим journal writer lock.
(*components.Manager).Quiescence(ctx context.Context, transactionID, component string) error
```

OPS реализует эти функции и native/test helper dispatch fixtures. CORE: добавить два private CLI branch **до** обычного server startup. Supervisor возвращает код; main завершает процесс через os.Exit. Probe печатает ограниченный результат и завершает процесс, не оставляет subreaper флаг у обычного daemon. Native capability/HIL запускает только координатор.

Acceptance контракт:

```go
components.ManagedRecoveryRequest{
    TransactionID: id, Component: component, Action: "accept-installed-idle",
    // существующие SafeMode/Stopped и fresh authority guard,
    QuiescenceCheck: func(c context.Context) error { return manager.Quiescence(c,id,component) },
    InactivityCheck: func(c context.Context) error { return appTrustedInactive(c,component) },
}
manager.RecoverManagedUpdate(ctx,request,freshAuthority,nil)
```

Новый terminal phase `accepted-installed-idle` и result `installed_idle_accepted=true`; **live_accepted=false**. Нужно добавить matching HTTP action и terminal checkpoint cleanup для этой фазы; отдельно включить UI label. Старые pending без candidate config snapshot не принимаются idle по одной версии. Нужны exact installed version/config + trusted inactive и quiescence до/после.

Существующий ManagedUpdateGuarded больше не использует candidate callback для acceptance rollback. По умолчанию known package/config compensation заканчивается `awaiting-rollback-acceptance`, `pending_rollback_acceptance=true`, ошибкой ErrRollbackUnconfirmed/ErrUpdatePending. Matching rollback/verify API остаётся независимым наблюдением. Дополнительный OPS API `ManagedUpdateGuardedWithRollback(ctx,id,candidate,authority,rollbackAcceptance)` разрешит отдельное trusted доказательство старого runtime, если приложение его действительно может предоставить; candidate probe сюда передавать нельзя.

OPS реализация завершена в этой порции. ComponentUpdateSchema=2: новый writer записывает v2; reader принимает retained v1 без новых полей. Historical v1 unknown без supervision сохраняет fence. Upgrade/rollback gate требует target -component-update-schema=2 при любом retained component journal, до stop и повторно после него. CORE CLI выводит эту constant и добавляет dispatch двух helper команд до startup. Старый schema=1 target больше не разрешается поверх новых journals/terminal phase.

Новый supervisor работает только с фиксированным production `/opt/var/lib/razvilka/components/update-journal`, matching private immutable command request и разрешённым opkg argv. Отдельный snapshot kernel lock исключает повторный helper. Перед запуском пакета durable armed identity; после wait4(-1) ECHILD — reaped receipt. При timeout helper очищает собственных детей; если не удалось подтвердить completion за bounded parent wait, исход остаётся unknown. Ordinary daemon не включает subreaper. Нет обязательного PID namespace/cgroup и нет PGID/empty-scan positive fallback. API Quiescence может создать постоянный lock inode; не меняет package/config/receipt, не kills/replays. Положительная same-boot проверка требует ECHILD; новый boot — только отсутствие старых процессов, не успех пакета.

Windows `go test ./internal/components` RC0; `go vet ./internal/components` RC0. Linux ARM64 test binary cross-compiled RC0. Shell syntax и real installer schema gates RC0. Linux process fixture и обновлённый настоящий opkg harness здесь НЕ выполнены. Координатору: `go test ./internal/components -run 'TestPackageSupervisionDetachedAndSupervisorDeath|TestSupervisionNewBootProvesOnlyInactivity' -count=1`, затем `scripts/test-component-update-native.sh`. Native normal path теперь требует pending rollback и отдельный matching verify; прежний native-opkg-04 pass не относится к этой supervision/acceptance семантике.

Основание subreaper/adoption: https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html. Бounded router capability probe выполнен координатором отдельно; полной native/power-cut гарантии это не даёт.
