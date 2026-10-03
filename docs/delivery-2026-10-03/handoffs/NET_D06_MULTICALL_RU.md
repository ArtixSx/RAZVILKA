# D06: invocation path служебных multicall утилит

Координатор подтвердил в VM: `/usr/sbin/modinfo -> /usr/bin/kmod`; исходный `modinfo -F name amneziawg` работает, а canonical `kmod amneziawg` и subcommand workaround — нет. Native-awg-01 RC1 возникал до dataplane: поля modinfo были пустыми после ошибочного canonical invocation.

Служебный lookup теперь отдельный: `LookPath -> Abs` сохраняет invocation symlink/argv0 для `modinfo`. AWG executable receipt по-прежнему использует `LookPath -> Abs -> EvalSymlinks` и exact SHA256. CheckRuntime и loaded==modinfo ограничения не ослаблены. Публичные capabilities выводятся до assertion в read-only native тесте и до создания namespace в AWG dataplane suite, в том числе при отказе gate.

Linux regression реально запускает контролируемый executable через symlink, проверяющий имя `$0`, затем подтверждает отказ прежнего canonical invocation. На Windows выполнены awgprofile tests/vet; Linux amd64 cross-compile awgprofile и vet awgprofile/dataplane PASS. Выполнение Linux regression и actual-native receipt остаются координатору. NET не управлял VM, module load или маршрутизатором.
