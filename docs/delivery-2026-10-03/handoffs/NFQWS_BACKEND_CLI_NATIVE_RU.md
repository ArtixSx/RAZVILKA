# Bounded backend CLI — ROOT-only native checkpoint, 07.10.2026

Следующая отдельная source/test порция после accepted partial observer `3e94a675c5eddbdd049467ed25647d60d165ce9d`. Production `RunBounded`, NFT transport, producer API, Manager/DEFAULT, network owner/authority/main/capability не менялись. Добавлены один Linux-only native test file и отдельный launcher. Родительская ветка содержит finished3e94; чужой WIP/DEFAULT source не мержился.

**Здесь native не запускался.** Local evidence: Linux amd64+arm64 test cross-compilation, Linux amd64 vet, Windows Backend/NFQWSScoped model regressions и shell syntax PASS. Это readiness к ROOT run, не actual CLI/kernel acceptance. Socket live VM hook отложен: текущий приоритет — actual CLI limits; modern NFT ABI здесь не объявлялся complete-empty.

## ROOT запуск

На exclusive Linux VM, ROOT, Go1.26.5 и доступные PID namespace/proc mount/unshare, pidfd APIs и child subreaper:

```sh
sh scripts/test-backend-inventory-cli-native.sh
```

Launcher использует explicit GOOS=linux/GOARCH=amd64 либо arm64, GOTOOLCHAIN=local/GOMAXPROCS=2/GOFLAGS=-p=2. Создаёт root-private0700 staging/TMPDIR, compiled dataplane.test0500 и hardlink backend-read-cli к **тому же** executable inode. Артефакты staging сохраняются; успешные t.TempDir case directories могут быть удалены Go testing. stdout теста содержит actual per-case elapsed/output/cleanup proof. Никакого iptables/nft/system package/router/kernel module вызова: argv `-t mangle -S` обрабатывает только immutable private test executable.

Сам test controller запускается как PID1 в отдельном `unshare --fork --pid --mount-proc --kill-child=SIGKILL`; исходный PID namespace записывается launcher из proc и сверяется. При отказе/timeout завершение namespace init убивает namespace descendants. Опция opt-in `RAZVILKA_BACKEND_CLI_NATIVE=1` и private role/path checks обязательны. Обычный Go test не активирует fixture; early CLI dispatch существует только в Linux `_test.go`, до testing flag parser и никогда в production binary.

## Девять actual сценариев

| Case | Обязательный oracle |
|---|---|
| valid | stdout17 bytes + stderr10 bytes в одном capture, exact text и nil error |
| stdout-overflow | stdout128KiB при cap32; internal cancel, error и nil returned output; original ctx жив |
| stderr-overflow | тот же limit на stderr; не отдельный неограниченный stderr buffer |
| combined-overflow | stdout16 + stderr16 + stderr1 при общем cap32; общий capture не допускает33 |
| deadline | actual private CLI сначала пишет prefix, затем удерживается; deadline350ms, error содержит DeadlineExceeded, output nil |
| cancel | cancel только после actual prefix/ready; error содержит Canceled, output nil |
| inherited-exit | CLI порождает detached leaf с обоими pipes, выходит0; WaitDelay100ms даёт ErrWaitDelay/output nil при живом caller ctx |
| inherited-cancel | caller cancel после готовности CLI+leaf; direct CLI Wait завершён, output nil; leaf всё ещё жив |
| inherited-deadline | deadline700ms после старта private subtree; output nil; leaf всё ещё жив |

Для каждого actual Run измеряется monotonic elapsed: ≤исходного budget +250ms (учитывает100ms pipe drain и scheduling margin). Actual identity record обязателен: boot/start/PID/group/exe/argv hash плюс parent. Отсутствие запуска/record не считается успешным deadline/overflow. Controller worker ограничен6s и16KiB собственного stdout+stderr. Worker result требует successful CLI direct Wait (второй exact Wait4 возвращает ECHILD), nil partial output на всех error paths и отдельный final fixture ECHILD. Errors остаются errors; это не нормализация production consumer result.

## Direct Wait и отдельный fixture cleanup

Каждый сценарий имеет **отдельный private setsid worker**, который единственный в этой fixture включает PR_SET_CHILD_SUBREAPER. Test controller/daemon этого не делают. Actual `nfqws2ExecRunner.RunBounded` по-прежнему выполняет sole command.Run/Wait для direct CLI; никаких hooks в production runner для теста не добавлено.

Для inherited cases CLI создаёт leaf в **новой session/group** с унаследованными pipes. Parent ждёт его exact identity/ready перед собственным exit/hold. После возврата RunBounded тест обязан увидеть живой leaf с прежними boot/start/group/exe/argv и parent, изменившимся лишь на private worker. Это explicit negative proof: **direct child kill/Wait и закрытие inherited pipe не означают quiescence descendants.**

Только после этого private worker удаляет recorded exact fixture birth: pidfd open + двухстороннее boot/start/group comparison → SIGKILL этому pidfd → bounded exact PID Wait4. Alive/zombie births не заменяются numeric-PID/group-wide cleanup; ошибки/переиспользование birth отказывают. Затем Wait4(-1,WNOHANG)=ECHILD подтверждает отсутствие children **этой controlled fixture**, где все children созданы normal Go exec. Это не generic production tree proof и не замена NFQWS ECHILD/ACK supervision ABI.

Failure recovery controller повторяет cleanup только recorded births, а затем требует свой ECHILD. Незарегистрированный child/ambiguous cleanup приводит к FAIL и завершению private PID namespace; следующий case не выполняется. Namespace lifetime — fallback для faulted test, не successful cleanup receipt. Ни один failure не выдаётся за full native PASS или разрешение consumer/LAN retirement.

## Что ROOT должен вернуть

Source pin, actual command/RC/log, nine per-case results и elapsed, direct Wait/leaf-alive/separate-cleanup outcome. Необходимые kernel APIs missing/unavailable дают fixture refusal, не skip→PASS. При actual failure source/test ремонт выполняется отдельным finished follow-up; локальная compile проверка не подменяет ROOT execution.

Shared inventory остаётся partial5-table library: arbitrary registered tables, protected tool review/ancestor/dependencies, exact firmware unsupported proof и полный LAN NamespaceCheck по предыдущему handoff всё ещё открыты. Этот process/pipe checkpoint их не расширяет.
