# Проверка интеграции 2aa2ba12

Проверен commit `2aa2ba1258d75bc520c79cc1006eb2cf36f1d5a2`.
Полный [push CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448791217)
и [PR CI](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448797720) завершились SUCCESS.
Это не означает завершение отдельных native-сценариев ниже или аппаратной приёмки.

| Сценарий | Фактический результат |
| --- | --- |
| Cold recovery, normal/race | [41448791547](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448791547) SUCCESS. Новый `TestMihomoLiveColdHealth9CLINativeHistoricalIntent`: normal 27,88 с, race 63,37 с. Это два разных режима, не сравнение ускорения. |
| Health history | [41448791316](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448791316) SUCCESS. |
| VLESS и WireGuard | Focused jobs 125288489039 и 125288489495 SUCCESS. |
| StrategyLab pair | Job 125288489399 остановлен на устаревшем shell assertion: текущий execution reader ожидался 8 вместо фактического 9. Целевые backup-тесты в этом job ещё не запускались. Ожидание исправлено в следующем пакете; нужен повтор. |
| Точная маршрутизация/DNS | [41448791101](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448791101) FAIL; незавершённое восстановление после failed setup не считается ready-cancel. |
| Managed NFQWS2 | Focused production/race jobs 125288489636/125288489565 FAIL. Полный LAN Apply не принят. |
| Mihomo warm lifecycle | [41448791156](https://github.com/ArtixSx/RAZVILKA/actions/runs/41448791156) FAIL. Post-CAS job 125288489828 не достиг нужного CAS: Health исчерпал deadline, rollback и verify-rollback прошли, получен 409 вместо ожидаемого 503. Это не подтверждение целевого post-CAS сценария на этом SHA. |

Cold health9 использует моделированную сохранённую историю старой загрузки.
Текущий CLI, пять исходных leases, наблюдения source/process/kernel, исходная
пара файлов, архив, fleet admission и проверка обязательного reader9 — настоящие.
Unknown/checking/retiring не получают разрешение из документарного заголовка.

Следующий пакет интегрирует отдельно проверенный same-boot original cursor,
явный minimum8/9, проверки исходных plan FD/отсутствующих имён в каждом delete
bookend и измерения фаз. На isolated ff2 normal recovery прошёл за 99,70 с,
race остановился на исходном 120-секундном deadline после двух terminal ACK;
ACK cuts были пропущены из-за неуспешного baseline. Это остаётся незавершённым.
Metadata restart и предыдущий stopped plan находятся в отдельной реализации.

Программного внешнего блокера у этих failures нет. Для физической приёмки нужны
выделенный роутер, LAN-клиент и отдельная авторизация: [сценарий](../../../ROUTER_ACCEPTANCE_RU.md).
