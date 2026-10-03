# D06: srcversion реального kbuild

В сообщённой координатором успешной сборке Ubuntu kernel 7.0.0-34-generic официальный pinned AWG модуль имеет `srcversion=8B43245B4272244B0CB9617` (23 символа). Это корректный результат kbuild, который прежний regex ровно24 ошибочно отвергал.

Первичный источник Linux v7.0: [modpost.h](https://raw.githubusercontent.com/torvalds/linux/v7.0/scripts/mod/modpost.h) задаёт `srcversion[25]`; [modpost.c](https://raw.githubusercontent.com/torvalds/linux/v7.0/scripts/mod/modpost.c) передаёт `sizeof(srcversion)-1`, то есть24, в [sumversion.c](https://raw.githubusercontent.com/torvalds/linux/v7.0/scripts/mod/sumversion.c). Его `snprintf` сохраняет место под NUL, поэтому получается23 hex-символа. Граница формата исправлена на23–24 hex, сохраняя известные24-символьные receipts. Более короткие, длинные и неhex строки отвергаются. Loaded sysfs и установленный modinfo по-прежнему сравниваются побайтово, без дополнения/усечения/смены регистра. Это метаданные происхождения, не криптографический digest модуля.

Добавлена регрессия с фактической23-символьной строкой из VM,24-символьным вариантом, разными/неверными значениями. `go test ./internal/awgprofile -count=1`, `go vet ./internal/awgprofile`, gofmt и `git diff --check`: PASS (Go1.26.5 Windows, GOMAXPROCS2/GOFLAGS-p=2). NET не устанавливал и не загружал модуль; native окно выполняет координатор.
