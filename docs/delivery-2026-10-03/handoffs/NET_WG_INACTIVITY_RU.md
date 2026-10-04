# NET: WG/AWG/WARP read-only inactivity observer

`(*WARPWireGuardAdapter).VerifyRuntimeInactive(context.Context) error` реализован отдельно от WG network WIP. DEFAULT должен вызывать его из общего Manager read-only aggregator под существующим operation admission; CORE использует только свежий результат. Сам observer ограничен 8 секундами и не выполняет Stop, repair, settle, удаление или запись private state.

Доказательство включает два свежих полных чтения вокруг process inventory:

- Все private WG ownership/runtime/reference должны либо отсутствовать, либо давать точный valid removal receipt без pending/unknown/promoted. При retained intent проверяются полный runtime hash, immutable reference и actual absence каждого общего policy tuple и outer endpoint. Неполные/осиротевшие файлы, WG operation и отсутствие receipt отказывают.
- Полный bounded JSON link inventory должен существовать и не содержать основной или canary интерфейс. Пустой/null/duplicate inventory не подтверждает отсутствие.
- Numeric RPDB обоих семейств не должен содержать own/shared/endpoint/canary priority namespace или неизвестные зависимости. Полные owned service table, dedicated outer table и canary219 должны быть пустыми в обоих семействах; foreign row/selector сохраняется и отказывает.
- Linux `/proc` inventory читает actual `exe` и bounded `cmdline`. Userspace wireguard-go/amneziawg-go, свой wg-quick/awg-quick wrapper и shell-command отказывают; подменённый argv[0] не скрывает actual executable. Ошибки доступа/частичное чтение/пустой inventory отказывают. Неподдерживаемая платформа отказывает, не подменяя это фиктивным отсутствием процессов. Наличие чужого userspace WG daemon консервативно удерживает общий inactivity proof.

Windows model tests `^TestWGInactivity` PASS: cold full absence; live/canary link; empty inventory; foreign route/selector/priority; unknown goto; failed readback/process; pending/private partial; retained exact removed receipt и отказ после потери receipt. Ни одна observer-команда не меняет runtime. Linux-specific tests actual exe и shell wrapper созданы и cross-compiled; Linux native/race/actual provider consumer выполняет Root. Windows/Linux vet и Linux amd64 test compilation проверены.

Это owner port для D11, не самостоятельный installer provider и не декларация D11 cap1. ScopedDNS runtime owner находится у LAN/DNS; NET DNS transport-hook не создаёт второй live state для него. WG network forwarding, frozen LAN activation и family service acceptance остаются отдельной работой.

Root review первоначального `b501103` обнаружил отказ cold adapter на несуществующей FIB table. Follow-up распознаёт только bounded exact `Error: ipv4|ipv6: FIB table does not exist.` (с optional `Dump terminated`/пустой JSON оболочкой), после чего независимо перечитывает **всю** ту же numeric table через существующий `readPolicyTable`. Любая строка маршрута, несовпадающее семейство, дополнительная ошибка, превышение bound или отмена отказывает. Регрессии обоих семейств подтверждают cold absence и сохраняют refusal для чужого маршрута в повторном чтении и похожих ошибок. Первоначальный commit до принятия follow-up считать held; actual ENOENT/native проверяет Root.
