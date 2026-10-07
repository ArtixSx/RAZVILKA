# DEFAULT: исходный допуск и намерение передачи NFQWS

База: принятый ROOT `e28e2f6`. Это первый исходниковый этап A;
обычный active NFQWS пока не подключён к `Manager.Apply`.

`NFQWSExecutionResource.configureActive` связывает отдельную active command
с исходным обычным execution, тем же runtime/nfqws2, полным typed network
identity и обязательным закрытым reader владельца lease3. Временные health /
canary execution и старый lease2 `Prepared` не могут получить active допуск.

`PreparedActive` потребляет независимое наблюдение действующего владельца
до разрешения capture. `BeginTransfer` однократно проверяет того же владельца,
LAN, typed queue и общий capture receipt через закрытый reader, затем пишет
`transfer-intent` в ОБА имеющихся execution journal. Проверка вызывается до
будущего Store CAS и публикации плана; сама интеграция CAS здесь отсутствует.
Отказ наблюдения или одной записи не допускает повтор этой передачи.

Scope удерживает защищённый открытый root с проверкой inode до/после открытия,
исходный путь Manager, конкретный зарегистрированный экземпляр адаптера и
тот же typed provider. Сравнение экземпляров использует существующий
`sameNetworkPolicyDependency`: одинаковое содержимое нового объекта не
сохраняет допуск. Повторная проверка после reader замечает позднюю отмену и
подмену исходного root/adapter.

`transfer-intent` и `transfer-ack` остаются nonterminal `prepared`. Сохранённое
наблюдение проверяет все восемь полей binding, полное typed identity и
helper/child birth; оно служит записью сравнения. Запись `ACTIVE` по-прежнему
отклоняется. Холодное восстановление не завершает передачу по совпавшему
committed plan и не исправляет metadata. Legacy timed flow сохраняется.

Проверки:

- Windows: связанные NetworkPolicy/NFQWS/Execution/Manager модели — PASS,
  38.637 s; новые отказные Transfer/ActiveScope модели — PASS, 0.610 s.
- Windows и Linux amd64/armv7: `go vet` dataplane/app — PASS.
- Linux amd64/armv7: test binaries dataplane собраны, затем удалены.
- Модели проверяют Start ACK, независимый reader, оба журнала, однократность,
  позднюю отмену, замену экземпляра/root, частичную запись и recovery fence.
  Настоящий процесс, очередь, provider и роутер здесь не запускались.

Оставшаяся работа B–E после принятого finished NFQ runtime pin:
удержание SAME scope от Activate до final ACK; исходный intent перед CAS;
provisional ACK в обоих nonterminal journal; конкретный sealed live handle;
проверка handle.Current перед ACTIVE/final execution; известный Stop/join и
receipt cleanup при финальном отказе. CORE original cleanup/control contracts
и полные kernel/receipt/LAN owner proofs обязательны на реальных границах.
