# Положительная роль external old0.19.3 installer

## Граница этой порции

Это read-only API классификации controller peer для полного native process
inventory: `SelfUpdateFileAdapter.VerifyInstallerControllerRole(ctx,id,pid)`.
Production constructor сохраняет фиксированные /opt roots. API не принимает
роль, birth/hash, caller bool, skipPID, environment grant или root override.
Оно не запускает процесс, не разрешает эффект, не принимает runtime/health и
не создаёт fake App. Actual external producer/CLI ещё не подключён; эта порция
нужна для согласования tiny CORE scanner wiring перед его подключением.

## Проверяемая связь

Review4 явно содержит role `external-old193-installer`, SHA кандидата и
физический путь/SHA проверенного внешнего архива. Helper SHA совпадает с
release binary digest и extracted asset map, отличается от old source SHA.
OldVersion строго 0.19.3; прежний бинарник не получает reader ABI. Review2
отвергает bootstrap binding. JournalReaders остаётся nil: stopped settlement3
не получает искусственного downgrade proof. Metadata floor такого review — 4.

Используется уже существующий `helper.identity.json`, привязанный к текущему
record/review: ID, helper PID, old panel PID, boot ID, start ticks, SHA, dev/ino.
Old panel identity должна быть снята producer до Stop. Его независимая birth
inactivity и отсутствие фиксированного PID-файла проверяются повторно.

Классифицируется только закрытая текущая группа:

- original entry: точные argv `self-update-bootstrap-old193 ID ARCHIVE SHA`,
  kernel identity совпадает с sealed helper identity;
- quiesce supervisor: точные argv `self-update-command-helper ID
  quiesce-old-runtime`, sealed process identity и настоящий kernel parent —
  original helper;
- quiesce child: точные argv `self-update-runtime-quiesce ID REVISION WORKER`,
  текущий DirectPID, настоящий kernel parent — sealed supervisor, candidate SHA.

Сам observer также обязан принадлежать этой группе. Arbitrary cold controller
не может прочитать ID и заимствовать чужую роль. Для live supervisor/child
нужны текущие receipt2 `running` и file receipt2 `command-started`, BeforeFiles,
точный quiesce command. Все три реальных процесса проверяются совместно.
Named/renamed/hard-linked/different-inode controller без этой связи остаётся
неподтверждённым. Process args/parent/hash/birth, review/record/identity, running
command receipt, matching file receipt и current Stop перечитываются вокруг
классификации.

ArchivePath/ArchiveSHA в review/argv — provenance потреблённого package, а не
требование повторно читать original archive при каждом scanner peer. Producer
обязан прочитать открытый no-follow original fd, проверить metadata/inode до и
после streaming copy/hash, fsync новой job copy и проверить digest до extract
или запуска bytes. После immutable review исходный внешний архив может быть
удалён/изменён: роль опирается на verified extracted images и review, не на
доступность original path. Role API не хеширует original archive и не заявляет
его текущую неизменность. Отказ changed-archive в role tests — изменение
checksum/path в exact argv binding, а не изменение внешнего файла после seal.

## Lifecycle и wiring

CORE вызывает API только с текущим конечным ctx, вне короткого control lock,
при обнаружении controller peer в строгом scanner. Отказ API — отказ полного
inventory, а не повод продолжить по имени/отсутствующему PID. Фактические DNS
port/socket/kernel проверки остаются обязательными.

`running` означает только подтверждённую живую служебную роль. Это не receipt
завершения и не ECHILD. Existing supervisor по-прежнему обязан реально joined
child tree и durable ECHILD до command inactivity/capture/replacement. API не
усыновляет dead helper/unknown worker и не переписывает receipt. Reaped, armed,
completed, cold-start, outer-child mismatch, reused birth и изменённый archive
path/checksum в argv отвергаются для worker роли.

## Проверки и незакрытые пункты

Windows portable owner/role fixtures проверяют положительную статическую связь
и перечисленные отказы; полный updatecheck PASS 47.276s, Windows vet PASS.
Linux amd64/arm64 vet + test compilation проверяют platform implementation;
`TestNativeBootstrapControllerRoleRefusesColdObserver` читает реальный observer
ELF/argv/birth, но retained old-panel facts в отрицательной фикстуре моделируются.
OPS ELF не запускает. Это не native bootstrap PASS.

Далее: настоящий producer verified archive → immutable review → original
helper/old panel identity до Stop; CORE tiny scanner/CLI wiring; Root actual
fixed-/opt native upgrade, paired public restore и crash/refusal acceptance.
Legacy UI helper/history не усыновляется и должен сохраняться как blocker.

Уточнение ba55 restore QA: required primary S99razvilka guard обязателен;
guards legacy init проверяются для присутствующих prior/current entries.
Отсутствующие legacy entries не становятся доказательством всех трёх guards.
