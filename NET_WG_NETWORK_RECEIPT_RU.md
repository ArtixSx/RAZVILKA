# WG/AWG: source CIDR, собственный SNAT и общая квитанция

Этот checkpoint добавляет network consumer к существующему WG/AWG executor.
Он предназначен для независимого review и Linux native проверки у Root.
Он не завершает D07, не объявляет D11 полностью готовым и не разрешает запуск
непроверенного сетевого пути на роутере.

## Полное намерение и ограничения

Stage получает полный `Plan.FrozenLAN()`, проверяет generation, source × ingress
и отдельную таблицу outer transport. Scalar role/generation не дают разрешения.
Должны быть покрыты все destination CIDR одной peer AllowedIPs, включая объединение
префиксов без дыр. Для каждого выбранного семейства нужен собственный адрес туннеля
и независимая UDP health destination, также покрытая AllowedIPs.

Для forwarding используется существующий общий bridge/assigned-prefix/member/WAN
compiler. Его запрет неподтверждённого public/GUA source subnet сохранён; IPv4 private
и IPv6 ULA полные CIDR покрыты моделями. CORE ещё готовит типизированное подтверждение
GUA source CIDR с полным immutable LAN payload и физическими наблюдениями. Нового
`includePublic` либо разрешения только по generation нет. WARP network consumer
здесь также явно отказывает; его транспортный owner — CLOUD.

## Одна durable authority

Network receipt использует уже принятый common schema 2, root, lock и boot identity.
WG reference сохраняет полный FrozenLAN, health implementation version и адреса
туннеля, выбранные для source NAT. Эти поля входят в immutable compiler identity.
Рouting, private firewall bodies и attachments входят в одну effect plan; отдельного
forwarding lease/file нет. Legacy WG receipts сохраняют schema 1 прежнего backend.

Полные таблицы 206/205 и dedicated endpoint tables 213/212 наблюдаются по IPv4 и
IPv6 с числовыми координатами. Inner table допускает только единственный exact
собственный default tuple; foreign specific route не может скрыться за успешным
sampled `/0` lookup. Cold FIB ENOENT принимается только по bounded exact family
diagnostic плюс независимой пустой полной числовой выборке. Совпадение интерфейса,
table slot либо ядра само по себе не создаёт cleanup или ownership permission.

## Source NAT и удаление

WG/AWG получает private chains из существующего forwarding compiler, привязанные
к adapter id и state root. NAT body использует только собственный IPv4/IPv6 адрес
туннеля: exact `SNAT --to-source`, exact source/destination/outgoing interface и
positive managed mark. NAT attachment ставится перед firmware NAT. Filter attachment
ставится в хвост FORWARD, сохраняя приоритет ранее установленных ACL.

Линейная DAG common plan удерживает все prerequisites, пока attachment неизвестен
либо активен. Reverse cleanup сначала закрывает filter, затем убирает NAT attachments,
bodies/chains, RPDB и defaults. Каждая body/chain deletion проверяет отсутствие
references. Unknown body/reference, duplicate attachment, foreign route, неизвестный
selector или private receipt сохраняют всю authority и запрещают предположительное
удаление. Нет flush, restart для проверки уже занятого peer или adoption по slot.

После durable `removed` ACK повтор продолжает ту же квитанцию. Прерывание на
`cleanup-intent` или после syscall без отсутствия-ACK остаётся неизвестным: повтор
не выводит право удаления из похожего kernel state. Endpoint и interface удаляются
только после подтверждённого снятия всей policy generation.

Временные health selectors также сохраняют prerequisites при потерянном ACK:
неизвестный add/delete RPDB не разрешает удалить соответствующий default или
candidate interface. Приватный candidate profile остаётся для разбора состояния.
После ошибки удаления selector cleanup не продолжает удаление его маршрута.

## Проверки и восстановление

Каждое выбранное семейство проходит TCP/service + fresh handshake и независимый
UDP DNS exchange из собственного адреса с bind к нужному WG interface. UDP health
не является клиентским DNS profile, exclusion либо fallback resolver. Для уже
принадлежащего процесса и совершенно того же профиля проверка использует живой
interface и временные собственные socket selectors: без второй копии ключа,
setconf или restart. Полные profile bytes, actual peer/endpoint/AllowedIPs/PSK,
fwmark, private reference, receipt, boot и kernel tuples проверяются свежими.

Named profile lifecycle использует принятые `eb9d127` + `0633783` guards. Background
Reconcile/Refresh не меняют generation или Digest сохранённого full LAN scope;
новое намерение classifier требует полного Apply. Causal rollback восстанавливает
старый FrozenLAN и новую common generation по полной сохранённой authority.

Модели проверяют `/24` + `/64`, whole table collisions, обе SNAT families, сохранение
firmware ACL/NAT, known и unknown cleanup cuts, чужие body/reference/duplicate,
отзыв review, profile coverage, UDP response identity и занятый peer. Модельные
callbacks не считаются реальным TCP/UDP, DNS ownership или LAN packet evidence.
AWG проверен отдельной моделью compiler namespace 205/212 и тем же common DAG;
это не доказательство native AWG lifecycle или доступности advanced backend.

Root требуется actual dual-family LAN client TCP+UDP, source NAT return path,
classifier admission/excluded clients, WAN transport pin, wrong-peer refusal,
same-peer canary без restart, mixed receipt cuts/retry и process restart. Проверки
old EndpointLifecycle подтверждают свою старую область и не заменяют этот native
network consumer или конечную ordinary manager/CORE/LAN/DNS интеграцию.

Зависимости checkpoint: accepted CORE `f182633` (numeric boot/link tuple), full LAN
DEFAULT `3581111` и named guards `eb9d127` + `0633783`. Linux native запускает Root;
на его Ubuntu fixture приватные файлы следует создавать через отдельный TMPDIR
под `/etc/wireguard/razvilka-native-...`, как в принятом EndpointLifecycle 58b.

## Исправления независимого review Root для `5e113ed`

Mixed preflight повторяет существующий numeric `verifyPolicyPrecedence(..., true)`
до первого routing/firewall effect. Отсутствие собственных exact tuples больше
не скрывает более ранний foreign selector либо занятый reserved priority slot.
Регрессии покрывают перехват69→table214 и чужие selectors в70/71 обеих семей.

Validate, Activate до остановки старого runtime, Reconcile до recovery mutation,
mixed preflight и live Health повторяют full `compileForwarding` текущих
connected/assigned bridge prefixes, members и WAN. Результат обязан совпасть
с frozen Forwarding. Уменьшение `/24`→`/25` или `/64`→`/65`, DOWN и WAN drift
отказывают до effects/probes; один успешный sample внутри нового prefix не даёт
разрешение на весь старый source CIDR. Exact receipt cleanup не требует такого
forward physical grant и сохраняет прежнюю causal authority.
