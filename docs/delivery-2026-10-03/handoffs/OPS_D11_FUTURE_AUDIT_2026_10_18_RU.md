# D11: точный статус будущего обновления, 18.10.2026

База — чистая **0.20.0**, кандидат — семантически выше неё. Старый bootstrap
≤0.19.3 не входит в приёмку. Этот аудит не меняет capability и не подтверждает
аппаратный результат. Проверены текущие OPS ordinary/file consumers, Main wiring
и shell upgrade/rollback; живой роутер и GitHub не использовались.

`-self-update-schema=0` в Main — намеренный отказ обещать общий capability2:
сырой shell replacement не получает authority только из reader4. В production
`Updater.prepare` уже есть отдельный узкий `ordinaryPreparation`: исходный
живой owner, версии >=0.20.0→строго выше, точные metadata0/reader4, config/Stop
epoch, архив и nine extracted hashes, staged migration и actual parent seal.
Он выдаёт Prepare/Ready, а не разрешение на raw upgrade или runtime acceptance.
Обычный helper, controller-role binding, runtime Deactivate/inactivity,
file command supervisor/Wait/ECHILD, paired prior images, stopped settlement
и startup consumers реализованы отдельно. Подмена schema0 на2 ничего из этого
не докажет и недопустима.

Конкретная найденная ошибка проверки: `test-self-update-native.sh` не выбирал
новые ordinary image-command/join тесты. Полный `check.sh` запускает Go suite,
но root-only image cases пропускаются без UID0. Новый отдельный
`scripts/test-self-update-ordinary-native.sh` требует isolated Linux UID0,
проверяет наличие четырёх тестов, запускает race и считает SKIP отказом.
Проверяются реальные Start/Wait, отзыв owner, same-byte inode replacement,
H→S→C identity/PID reuse и original joined callback после actual ECHILD.
Это private synthetic fixtures, не настоящий future release.

Недостающие production **доказательства**, а не доказанные отсутствующие функции:

- Четыре настоящих clean0.20.0→higher прогона: manual/automatic × success/rollback,
  с genuine release pair и production Main/HTTP/helper, без metadata doubles.
- Независимый recovery после прерывания до/после file-effect и commit границ;
  unknown outcome сохраняет fence, исходные journals, prior images и Stop epoch.
- Реальный Stop во время операции, join исходных владельцев, полная независимая
  runtime inactivity всех зарегистрированных NFQ/proxy/LAN/DNS владельцев,
  stopped rollback и явный допустимый Resume. API success без readback недостаточен.
- Настройки, secrets, sources, exclusions, node/component/package journals и LKG
  после update/rollback должны сохраняться; новая ревизия исключений запрещает
  восстановление прежних маршрутов. Повторный cold start не повторяет effects.
- AArch64 target acceptance; MIPS/MIPSel без устройства остаются cross-build-only.

По static audit нельзя честно назвать ещё отсутствующий production provider:
ordinary wiring уже присутствует. Следующий конкретный кодовый дефект должен
определяться первой настоящей отказавшей фазой, с сохранением evidence и authority,
а не предположительным ослаблением guard. Native private gate выше закрывает
только найденный пробел запуска тестов. `check.sh`, schema0, официальный релиз
и успешная DEV binary replacement не заменяют перечисленную D11 приёмку.

Команды в isolated Linux source tree:

```sh
sudo -n env GO=/absolute/go/bin/go sh scripts/test-self-update-ordinary-native.sh
sh scripts/test-self-update-native.sh
sh scripts/check.sh
```

Новые script/аудит требуют отдельного Linux запуска на своём commit; ранее
полученный Linux610 PASS не переносится на них автоматически.

Локально: `bash -n` нового runner PASS; Linux amd64 CGO0 `go test -c
./internal/updatecheck` PASS. Linux race/root fixture и genuine future release
на этом изменении OPS не запускал; их результат должен приложить координатор.
