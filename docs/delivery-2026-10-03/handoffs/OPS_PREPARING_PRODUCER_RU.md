# OPS: чтение реального preparing producer, 2026-10-09

Исправлена последовательность, используемая `Updater.prepare -> stageFileReview`.
До возврата stageFileReview текущая запись имеет state=preparing/stage=preflight,
а Files, ExecutableHash и FileReviewSHA256 ещё не опубликованы. Требовать
запечатанный review при проверке prospective reader proof означало остановить
нормальную подготовку до его создания.

Форматный читатель распознаёт только закрытую форму такого заголовка и набор
подготовительных артефактов. Контекст, отсутствие helper PID/apply token, flags,
channel, fingerprint и layout проверяются. Unknown stage, опубликованный digest
без matching review, process/private recovery/retained-helper или посторонние
элементы отказывают. Начальный header-before-job-directory cut читается только
на стадии metadata и не создаёт каталог.

Это разрешение на чтение формата. Default fleet по-прежнему блокирует pending
job; только существующий matching pending-ID view может включать prospective
контроллеры с их физическими SHA. Ready/effect authority требует опубликованного
immutable review. Retained4 продолжает требовать actual reader4; reader3, unknown
и future отказ не менялись. После записи file-review.json, но до публикации
current.FileReviewSHA, uncommitted cut снова отказывает.

Production wrapper теперь вызывает один private adapter method с тем же
producer body; production paths остаются прежними фиксированными /opt roots.
Это даёт native fixture собственные TempDir roots без CLI override и без замены
migration/capability commands тестовыми callbacks.

`TestNativeStageFileReviewBeforeCurrentReviewPublication` вызывает этот producer,
исполняет копии фактического ELF теста для migration и всех capability/read
probes, проверяет finite original scope/epoch admission и owner publication.
Migration fixture меняет только форматирование JSON; это проверка реального
producer, а не acceptance миграции реального 0.19.3 или live router.

OPS: полный Windows updatecheck PASS42.122s; focused preparing/paired-next tests
PASS4.388s; Windows vet PASS; Linux amd64/arm64 vet и test-build PASS без запуска
ELF. Native producer execution выполняет Root. Остальные complete-copy,
retirement, Stop, orphan и bare-Store fences сохранены.

Внешний first upgrade 0.19.3 и full paired offline restore всё ещё отдельная
незавершённая работа. Новый preparing reader не принимает старого UI helper как
современного владельца, не выводит его из fleet и не публикует продукт.
