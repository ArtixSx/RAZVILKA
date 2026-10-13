# Подготовка выпуска 0.20.0 — актуальный handoff OPS

Актуализировано: **13.10.2026 (Москва)**, исходник Root `2bfefb9dd2404da43e870f3548f553dbaa2bbb6a`. Исторический snapshot 07.10 сохранён ниже.

Целевой выпуск — **0.20.0**. По прямому указанию владельца переход с `0.19.3` и ниже исключён из действующего задания. Порядок проверки: **чистая 0.20.0 → ручное и автоматическое обновление выше 0.20 → восстановление и откат согласованной пары программы и состояния**. Root выполняет ранее разрешённые пользователем публикацию и удаление старых сборок после требуемых проверок.

## Подтверждённый статус и оставшаяся приёмка

| Проверка | Подтверждение | Граница результата |
| --- | --- | --- |
| Чистая установка и удаление | Native isolated fixture Linux425 — PASS; настоящие ARM64/AMD64 пакеты пары 0.20.0/0.20.1 | Linux-стенд |
| Ручное обновление 0.20.0 → 0.20.1 | Future426 — RC0 на `7a5bcfb317a8f2ddcea1a6cde3917d2ea39e853f`; завершение транзакции, история подключений и последующая запись настроек с CAS | Linux-стенд с частным HTTPS-источником |
| Обновление по расписанию 0.20.0 → 0.20.1 | Future434 — RC0 на `ed59f272d0f68b5cdccfb0d08c37d0ea5eadb334`; завершение установки, private data, история, прежние согласие/расписание и последующая запись настроек с CAS | Linux-стенд с частным HTTPS-источником |
| Проверка места при исчезновении временного файла | Linux430 на `ed59f272` — native `TestUpdateSpace -race` PASS 1.322s, vet и сборки ARM64/AMD64 PASS | Адресная проверка; исходный errno Future427 неизвестен |
| Настоящий отказ candidate и rollback | Остаётся проверить. Future431 не увидел окно отказа, сигнал не отправлялся; обновление завершилось | Future431 не подтверждает откат |
| Установленный роутер, час Telegram через выбранный VLESS, итоговые assets | Остаются по действующему плану | Future426/434 не являются роутерной или часовой приёмкой |

Подробные факты, package hashes и журналы: [VALIDATION_RU.md](../VALIDATION_RU.md). Актуальный объём и оставшиеся работы: [SUPPLEMENT_2026-10-13_RU.md](../SUPPLEMENT_2026-10-13_RU.md), [COORDINATION_RU.md](../COORDINATION_RU.md).

## Архитектуры и существующая упаковка

Требуются три роутерные архитектуры: **ARM64, MIPS и MIPSel**. AMD64 нужен отдельно для нативного Linux-стенда. В [build.sh](../../../build.sh) и [Release workflow](../../../.github/workflows/release.yml) перечислены четыре бинарника и 10 attached assets; наличие target в матрице не подтверждает работающий сетевой исполнитель или аппаратную приёмку.

| Назначение | Target / asset | Текущий подтверждённый объём |
| --- | --- | --- |
| ARM64 | `arm64` / `razvilka-linux-arm64` | Сборки текущей пары PASS; итоговая роутерная/часовая приёмка остаётся |
| MIPS, big endian | `mips`, `GOMIPS=softfloat` / `razvilka-linux-mips` | По текущему плану остаются реализация сетевого исполнителя и аппаратная проверка |
| MIPSel, little endian | `mipsle`, `GOMIPS=softfloat` / `razvilka-linux-mipsle` | По текущему плану остаются реализация сетевого исполнителя и аппаратная проверка |
| Linux-стенд | `amd64` / `razvilka-linux-amd64` | Native Linux fixtures; не роутерная архитектура |

При неоднозначном `uname=mips` существующий installer определяет endian по ELF-заголовку локального shell, отказывает на неизвестном/неполном заголовке и поддерживает явный `RAZVILKA_ARCH`. Сценарии проверки: [test-installer-architecture.sh](../../../scripts/test-installer-architecture.sh), [test-bootstrap.sh](../../../scripts/test-bootstrap.sh). Cross-build и shell fixture не заменяют физическую MIPS/MIPSel-приёмку.

Workflow запускает полный `scripts/check.sh`, проверяет metadata/version и manifest, пакует tar.gz/zip и bootstrap alias, создаёт checksums/attestations и draft с `latest=false`. Bootstrap берёт bundle и checksum одного release. Порядок и контракты: [правила версий](../../VERSIONING_RU.md), [установка](../../INSTALL_RU.md), [LAB](../../../LAB.md).

## Действующий checklist Root

- [ ] Закрыть оставшиеся работы плана и production blockers; записать итоговый source SHA и точные native logs. На чистой 0.20 проверить будущий выпуск выше 0.20 и настоящий отказ/rollback, сохранение private data, истории и настроек, штатные Stop/Pending/recovery. Future426/434 сохранить как подтверждённые этапы.
- [ ] На итоговых исходниках выполнить полный native `scripts/check.sh` и требуемые адресные проверки; сохранить фактические статусы всех трёх роутерных архитектур и отдельного AMD64-стенда.
- [ ] Провести требуемый час реального Telegram через выбранный VLESS на AArch64: точный бинарник/hash, revision, начало/конец, подтверждённый путь и cleanup, клиент/узел без секретов. Указать только реально проверенные сообщения/медиа/звонки; HTTP/TCP probe не подтверждает этот час.
- [ ] После требуемых native/hour проверок получить final artifacts из итогового SHA. Согласовать `VERSION`, metadata/UI, README/README_EN и release notes с фактами чистой установки, будущего обновления/rollback и реально доступного recovery. В этом doc leaf эти файлы не меняются.
- [ ] Сверить version/commit/SHA-256/attestations, три роутерных binaries и статус AMD64, soft-float targets, manifest и tar/zip/alias checksums, отсутствие private files/links. Сопоставить ARM64 asset с бинарником часовой приёмки; при изменении metadata/hash проверить точный attached asset.
- [ ] Выполнить разрешённую публикацию verified `v0.20.0`: проверить тег, снять draft и назначить Latest после требуемых проверок. Проверить `/releases/latest`, pinned/bootstrap download и свежую установку в согласованном порядке. Существующий тег не двигать.
- [ ] После успешной публикации нового verified Latest удалить старые build assets по свежему inventory, прежний Latest — последним. Сохранить Git tags/history и приёмочные hashes/logs; Release entries/notes можно сохранить. Source history, локальные router backups и компоненты в эту очистку не входят.

## Исторический snapshot 07.10.2026

На 07.10 OPS проверял source pin `1a3fdd26f948f4dd55331c42d44a621d1f45dbd6`; release/install/build/README файлы совпадали с OPS `92a3c4e`. Тогда задание включало переход `0.19.3 → 0.20.0`; последующее прямое указание владельца исключило его из действующего checklist. Предложение номера `0.2.0` было отменено в пользу `0.20.0`.

OPS source audit не обнаружил ошибки installer/packaging в том scope. Shell syntax, `test-build-targets.sh` с recording fake Go и `test-bootstrap.sh` с recording network/opkg/process fixtures прошли. Это не MIPS compilation и не native/router acceptance; Windows MSYS не выполнил bounded production reader probe с `RLIMIT_FSIZE`.

Authenticated REST audit **на 07.10**, сохранённый как история: [releases API](https://api.github.com/repos/ArtixSx/RAZVILKA/releases?per_page=100), [тогдашний Latest v0.19.3](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.19.3). Default branch `main`, SHA `817783493f0c2784ccc70aa73868cd64e9437634`; v0.19.3 опубликован `2026-09-30T10:02:46Z`. Получены 21 release и 208 uploaded assets, все `draft=false`, `prerelease=false`. Автоматические Source code archives в 208 не входят. Перед очисткой Root перечитывает inventory; таблица ниже не является текущим состоянием GitHub.

| Старый tag | Release ID | Uploaded assets |
| --- | ---: | ---: |
| v0.19.3 — Latest на 07.10, очистить последним | 399917317 | 10 |
| v0.19.2 | 399856653 | 10 |
| v0.19.1 | 399193472 | 10 |
| v0.19.0 | 399147958 | 10 |
| v0.18.19 | 398953728 | 10 |
| v0.18.18 | 398898823 | 10 |
| v0.18.17 | 398807820 | 10 |
| v0.18.16 | 398787555 | 10 |
| v0.18.15 | 398686787 | 10 |
| v0.18.14 | 398659504 | 10 |
| v0.18.13 | 397523586 | 10 |
| v0.18.12 | 397516751 | 10 |
| v0.18.9 | 392261448 | 10 |
| v0.18.6 | 392237824 | 10 |
| v0.18.5 | 392222530 | 10 |
| v0.18.0 | 379204680 | 10 |
| v0.17.0 | 379097673 | 10 |
| v0.16.0 | 376768277 | 10 |
| v0.15.1 | 376592349 | 10 |
| v0.15.0 | 376002597 | 10 |
| v0.0.8-security-gate | 369439960 | 8 |

Исторический комплект для каждого tag (V — tag без `v`):

```text
razvilka-linux-amd64
razvilka-linux-arm64
razvilka-linux-mips
razvilka-linux-mipsle
SHA256SUMS
RAZVILKA-V-entware.tar.gz
RAZVILKA-V-entware.zip
RAZVILKA-V.SHA256SUMS
RAZVILKA-entware.tar.gz
RAZVILKA-entware.tar.gz.sha256
```

У `v0.0.8-security-gate` два последних alias assets отсутствовали. При очистке сверяется целый согласованный комплект, чтобы checksum/alias не остался связан со старым binary. Новый release не входит в old inventory; `--cleanup-tag` не используется.

История CHANGELOG также фиксировала удалённый failed draft `0.18.2` и семь prereleases 19 сентября. На 07.10 этих семи entries уже не было в inventory; они не становятся новыми целями удаления.

Этот handoff обновлён только по исходникам и сохранённым фактам Root. В рамках doc leaf сборки, API/GitHub, VM/роутер и изменение версий не выполнялись.
