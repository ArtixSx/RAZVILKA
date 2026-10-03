# Фактическая проверка исходного комплекта

Дата:30.09.2026; база0.19.3 /817783493f0c2784ccc70aa73868cd64e9437634.

## Исполнено здесь

- **41 Go test function** в отдельном тестовом модуле: registry, typed outcomes, fail-stop batch, canary helper, catalogue envelope, точный DNS-модуль, точный memory inspector, точный callback config и новый App batch adapter.
- `go test -v -count=1 ./...` — exit0.
- `go test -race -count=3 ./...` — exit0.
- `go vet ./...` — exit0.
- **16 Python unittest**: включая настоящий локальный Git fetch/checkout в новой временной копии, diff и полный ZIP синтетического тестового репозитория; отказ при dirty/newer/source-nested output; несовпадающие hashes/anchors, traversal/symlink, повтор, unmanifested payload.
- Gofmt новых Go-файлов — чистый; JSON/граф зависимостей/ссылки задач — проверены.
- Полные локально сохранённые оригиналы config callback, DNS и resources сверены по Git blob. Остальные модификации привязаны к blob коннектора; сборщик обязан повторно проверить их перед применением.

## Обвязка, которая заменена тестовыми моделями

App tests используют настоящую новую функцию-адаптер, но модель Store/policy/IO/updater. Config tests вызывают точную изменённую функцию с тестовым Store/persistence. Эти проверки не охватывают полный App/coordinator/restorejournal. Native WG peer и фактический HTTP-трафик в canary-тестах подставные. Envelope-проверки не равны полному community+ownedfs runtime; repo-тесты для него приложены, но здесь не запускались.

## Не выполнено

Полный checkout/public download в этой среде; применение всего комплекта к полному текущему репозиторию; `go test ./...`/full scripts/check.sh RAZVILKA на Go1.26.5; реальные Xray/WG/AWG/USQUE/Mihomo/HEV; работа всех сайтов; package install/rollback через opkg; router/client HIL;24/72h. Тестовый Go1.23.2 модуль не понижает и не заменяет целевой go.mod. Новые 85 интеграционных/native/HIL сценариев имеют not_run.

## Состав

15 существующих файлов изменяются через 57 exact-anchor operations;19 новых Go-файлов (8 исходных +11 test files). Центральные CURRENT_STATUS/ROADMAP/V2 EXECUTION получают честное дополнение; история не переписывается. 17 оставшихся задач и28 source references (22 внешних,6 базовых файлов). Это не построчный аудит22 репозиториев; уровень чтения каждой записи различается и указан.

Контрольные суммы удостоверяют целостность комплекта, а не его аппаратную готовность/подпись. Синтетический end-to-end тест сборщика не является выполненной сборкой полного реального проекта.

Финальная проверка доставки: архив распакован в новую временную директорию; checksum verify →16 Python tests →41 Go tests/race/vet →checksum verify завершились с кодом0. Повтор тестов не изменяет вложенные исходные журналы. Это по-прежнему не full RAZVILKA CI.
