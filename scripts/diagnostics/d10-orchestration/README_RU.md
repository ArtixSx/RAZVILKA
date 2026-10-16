# D10: приватная офлайн-подготовка координатором

`prepare.py` ничего не запускает, не соединяется с сетью, не публикует feed,
не меняет firewall и не отправляет команды нативному тесту. Созданные JSON,
сценарий запуска и intent-файлы — данные оператора, не native evidence и не
полномочия на удаление. Запускать подготовку на Linux от root; выводить секретные
файлы в чат, общий каталог или stdout нельзя. Production не изменяется.

Нужны три свежих BLACK VLESS TCP профиля в canonical single-outbound JSON:
A действительно работает, B независимо даёт определённый отказ, C работает и
имеет другой публичный numeric `server:server_port`. Все три tuple различны,
обычный TLS включён, `insecure` запрещён. Доступность проверяет координатор,
офлайн-парсер этого не доказывает. Сценарий намеренно не поддерживает WS/gRPC,
DNS endpoint или другие протоколы.

Нужны также отдельный публичный HTTPS:443 feed с нормальной проверкой TLS,
подконтрольная выдача только AB, затем только C по тому же URL; реальные копии
catalog/sources; настоящий scope одного известного Home устройства/сегмента с
`selected_devices`, `new_devices=base`, `selected_services`, без отдельных правил.
Адрес выбранного ПК должен реально принадлежать этому устройству. У всех файлов
входов — root owner, 0600; они находятся вне будущего пустого native root.

Создать приватный `manifest.json` (0600) по шаблону ниже, заменив только локальные
пути и согласованные адреса. Значения адресов здесь — пример, не согласование цели:

```json
{"schema":1,"run_id":"root-auto-unique-012345","router_run":"/opt/var/qa/d10-unique","router_binary":"/opt/var/qa/native-cmd.test","profile_a":"/private/d10/a.json","profile_b":"/private/d10/b.json","profile_c":"/private/d10/c.json","feed_url_file":"/private/d10/feed-url.txt","catalog":"/private/d10/catalog.json","sources":"/private/d10/sources.json","scope":"/private/d10/scope.json","client_ipv4":"192.168.1.40","https_ipv4":"1.1.1.1"}
```

```sh
umask 077
python3 prepare.py prepare --manifest /private/d10/manifest.json --out /private/d10/package
python3 -m unittest -v test_prepare.py
```

Пакет создаётся только в новом каталоге 0700; каждый файл 0600. В нём:
`inputs/`, AB/C тела и hash allowlist в `feed/`, начальный `control.json` с AB,
кандидат `C.control.next.json`, `native.env.json`, `native.argv.json`,
`native-run.sh`, `fault-plan.private.json`. Старый пакет не перезаписывается.
После ошибки частичный пакет сохраняется для проверки и не считается готовым.
`native-run.sh` ещё не запущен и не доказывает перенос/проверку бинарника.

Последовательность координатора:

1. Проверить свежие A/B/C, SHA/source нативного бинарника, отсутствие чужих
   соединений к QA tuple A. Сохранить полные private BEFORE: kernel rules/routes,
   stock `nwg0`, процессы, основной config и установленный executable hash.
   Не запускать второй panel/coordinator. Подготовить обычный HTTPS сервер,
   выдающий ровно тело AB по приватному URL; запретить directory listing и
   публикацию `inputs/`. Проверить настоящий TLS/HTTP200/body SHA извне.
2. Перенести пакет в `router_run`, сохраняя права. Создать `router_run/qa` как
   пустой root-owned 0700. Использовать **уже проверенный** detached root waiter
   с текущим NETWORK namespace и отдельным MOUNT namespace. Он запускает
   `/bin/sh native-run.sh` без общего process-killing timeout. Сценарий использует
   `-test.timeout=0` и пишет `actual-exit` только после настоящего возврата теста.
   Наличие PID или закончившееся окно наблюдения не равно join.
3. Читать настоящий `qa/qa-auto-control/status`. При `applied_a` и двух реальных
   retained A rechecks координатор вставляет **один** согласованный fault для
   exclusive QA A tuple. `fault-plan.private.json` содержит лишь предложенный
   точный OUTPUT TCP `/32:dport` selector с уникальным comment и обратный argv.
   Координатор отдельно проверяет поддержку REJECT/TCP reset и сохраняет ACK
   именно своего успешного insert. Чужие цепочки не flush/restore; B/C/SSH/WG
   selectors не затрагивать. Не угадывать владение по позднему `-C`/наблюдению.
4. Скопировать настоящий status в приватный файл оператора. Подготовить intent:

   ```sh
   python3 prepare.py command --package /private/d10/package --status /private/d10/actual-status.json --verb FAULT_A
   ```

   Только после настоящего fault ACK атомарно перенести `FAULT_A.intent` в
   `qa/qa-auto-control/command` (0600). Программа сама ничего туда не отправляет.
5. Ждать `exhausted_ab`: свежая непрерванная пара отказов A, последующий B и
   настоящий exhausted traversal. Только теперь координатор переключает тот же
   публичный feed на C, проверяет HTTPS200 и **C-only** SHA. `C.control.next.json`
   — кандидат для его сервера, не ACK публикации. После реального ACK подготовить
   `PUBLISHED_C.intent` тем же способом и атомарно перенести как command.
   Не вызывать QueueSync/import/manual check, не менять due/cooldown/clock.
6. Настоящий тест требует обычный demand job не раньше 15 минут от bootstrap,
   новый HTTP200 body, admit/check/commit C и два retained C rechecks. В фазе
   `committed_c` проверить с **реального выбранного ПК** существующим LAN oracle:

   ```sh
   telegram-soak --lan-client PC_IPV4 -telegram-ip AGREED_PUBLIC_PIN -mtproto -duration 2m -interval 10s
   ```

   Это отдельный отчёт с привязанными к UTC выборками, TLS/MTProto результатами
   и счётчиками исходного C пути; SOCKS/router OUTPUT не заменяет LAN. Здесь нет
   обещания часа, авторизованного Telegram или непрерывности при смене A→C.
7. После проверки координатор создаёт `STOP.intent` по настоящему `committed_c`
   status и переносит его как command. `ABORT` доступен при неуспехе, но это
   intent, не kill. Тест обязан сам завершить public Stop/durable job, исходные
   worker/retained Close и DNS join. Не убивать процесс по окончании монитора.
8. Требовать одновременно статус `retired`, настоящий `actual-exit=0`,
   подтверждённый join и private AFTER. Удалять только свой A fault по сохранённому
   ACK исходного insert; обратный argv из плана сам по себе этого права не даёт.
   Неизвестный ACK/cleanup, `failed_retired` или живой keeper оставляют FAIL/unknown,
   артефакты и исходного владельца. Сравнить сеть/config/hash и чужой `nwg0` с BEFORE.

Блокеры до native запуска: нет свежих независимых peer tuple; нет реального
HTTPS443/TLS или контроля C-only публикации; scope/ПК не соответствуют; не проверен
detached waiter; не обеспечены original fault ACK/точечная очистка. Сам успешный
`prepare` ни один из этих блокеров не снимает.
