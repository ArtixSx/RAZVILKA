package dataplane

import "time"

// GracefulShutdownBudget lets an already-entered live phase settle, then lets
// its cancellation rollback finish, with time for final journal publication
// and joining workers. Cancellation prevents admission of another forward
// phase, so shutdown does not budget for an entire multi-adapter transaction.
// This covers the default Manager budgets: a longer RollbackTimeout override
// needs a matching shutdown grace. Blocking filesystem/kernel calls must also
// return; context deadlines cannot impose a hard bound on those calls.
const GracefulShutdownBudget = liveMutationBudget + defaultRollbackTimeout + 30*time.Second
