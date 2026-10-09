# Строгий scanner группы external installer

Родитель: `a15f5bccc7acfc6b97ca3de847a8cf5020ecc06f`. Зависимость API — OPS `bc935a35031b890be5e49f618a1fefa69f65a175` и его role dependencies, уже входящие в исходный Root `10acec04`.

Только приватный Manager self-update observer подключает конкретный production `*updatecheck.SelfUpdateFileAdapter` к своему зарегистрированному ScopedDNSAdapter. Binder фиксирует ID и исходный конечный context/deadline, отказывает повторному bind и живой DNS session; публичного callback, роли, списка PID или флага допуска нет.

Полный `/proc` scanner сначала читает исходные stat/argv/exe. Совпадающий inode, имя контроллера, ссылки на runtime roots или точный installer command marker требуют положительного `VerifyInstallerControllerRole` для найденного PID. Marker нужен также для настоящего installer с другим basename/inode; сам marker роль не доказывает. После исходных argv/exe/stat bookends роль проверяется повторно. Все остальные процессы, socket tables, сохранённые файлы, типизированная network identity и complete kernel inventory остаются обязательными.

OPS reader сам проверяет настоящего наблюдателя и peer, неизменяемый review/helper/command group, protected epoch, отсутствие старого panel и исходные `/proc` факты. Reader вызывается вне control effect lock. Обычный startup не получает этот binder; cold/outer/unknown controller остаётся отказом.

Проверки: Windows ScopedDNS inactive/installer models 5.455s; command/self-update tests 2.349s; Windows и Linux arm64 vet для cmd/dataplane. Модели проверяют named/same-inode/different installer image, обязательные closing proofs, изменение argv/stat, отказ роли, других процессов, socket ABI и kernel inventory, истечение/copy исходного carrier. Native migration не запускалась.

Остаются adapter-bound paired App Current/Action hooks. Этот scanner не доказывает ECHILD, здоровье dataplane или право retirement; offline requires-review никогда не допускает retirement.
