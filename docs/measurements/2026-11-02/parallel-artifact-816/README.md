# Парное измерение полного чтения и SHA-256 двух файлов

Источник: commit `8162538c0a1385e1e8d2aa10945ee970274a01f0`, [native run 41447514347 / job 125284180077](https://github.com/ArtixSx/RAZVILKA/actions/runs/41447514347/job/125284180077), 2026-11-02. SHA-256 полного скачанного job log: `d7cef0b3c23e041eab740287db4fe00068e390b6a1a09573edfd76567ea3d6c9`.

Измеряется библиотечный read-only вызов на двух настоящих защищённых файлах по 67 108 844 байта с одинаковым сгенерированным содержимым. Оба алгоритма полностью хэшируют установленный файл и файл артефакта, проверяют исходные дескрипторы и вызывают один и тот же `MatchHeld`. Reference: `WithReadComparison`, последовательное чтение. Новый вариант: `WithExpectedReadComparison`, два независимых FD/ReadAt, полный join перед callback и возвратом. Объём чтений и количество полных SHA сохранены.

Linux CI, Go 1.26.5, `cpu_count=4`, `GOMAXPROCS=2`, N=12 на алгоритм в каждом режиме. Порядок reference/new чередуется. Файлы перед измерением созданы и установлены через реальный CAS, поэтому замеры используют прогретый файловый кэш. p50/p95 — nearest-rank: элементы 6 и 12 после сортировки 12 значений. Единица — миллисекунды.

| Режим | Алгоритм | p50 | p95 |
|---|---|---:|---:|
| normal | последовательный | 115.502 | 121.091 |
| normal | параллельный | 62.771 | 79.557 |
| race | последовательный | 147.100 | 156.299 |
| race | параллельный | 82.038 | 86.057 |

Воспроизведение на Linux с доступом к обычным приватным файлам:

```sh
RAZVILKA_ARTIFACT_EXPECTED_TIMING=1 go test -count=1 -v ./internal/restorejournal -run '^TestArtifactExpectedReadComparisonPairedWall$'
RAZVILKA_ARTIFACT_EXPECTED_TIMING=1 go test -race -count=1 -v ./internal/restorejournal -run '^TestArtifactExpectedReadComparisonPairedWall$'
```

`normal.csv` и `race.csv` содержат все 48 значений. `raw-library.log` сохраняет исходные строки окружения, результатов, статусов тестов и измерений с временными метками job.

На том же commit проверки реальных дескрипторов, mutation/replacement, ошибок одного reader, panic/cancel/join и отзыва comparison прошли normal/race. Полный live-сценарий Mihomo ещё не завершён: один runner упёрся в прежний лимит Apply 110 секунд, другой завершил Apply, но получил отказ второго Stop после проверенных fault cuts. Данные здесь подтверждают ускорение библиотечного хэширования; готовность полного lifecycle и работа на роутере требуют отдельных успешных проверок. CPU/RSS этого библиотечного замера не снимались.
