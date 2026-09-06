# PR-NFQ0 — baseline управляемого NFQWS2

Этот документ фиксирует исходное состояние перед изменением представления
NFQWS2. PR-NFQ0 не меняет firewall, NFQUEUE, конфигурацию, процессы или lifecycle.

## Воспроизводимые состояния

Три обезличенных fixture находятся в `internal/engine/testdata/nfqws2`:

1. `native-managed` — установленный и запущенный NFQWS2 под управлением
   RAZVILKA;
2. `external-z2k` — сторонний владелец NFQUEUE, доступный только для наблюдения
   и локального импорта;
3. `missing` — NFQWS2 не установлен, поэтому runtime, native-check и работа
   маршрута не заявляются.

Fixture не содержит рабочей стратегии, ключей, URL загрузки или команды запуска.
Внешний owner не появляется в списке выбираемых обходов.

## Аппаратный baseline 2026-09-06

Read-only снимок снят на тестовом Keenetic/Netcraze до PR-NFQ1:

- архитектура `arm64`, kernel `4.9-ndm-5`, WAN `eth3`;
- доступны `iptables`, `ip6tables`, NFQUEUE и TUN; `nftables`, `ipset`, TPROXY
  и socket-match не заявлены;
- NFQWS2 найден в `/opt/usr/bin/nfqws2`, сконфигурирован и запущен;
- native-check доступен, заявлены TCP, UDP, DPI-desync и NFQUEUE;
- внешний z2k не обнаружен, preview остаётся read-only;
- на момент снимка присутствовали внешние tunnel-интерфейсы, поэтому честный
  DIRECT-контроль обязан учитывать загрязнение маршрута.

Снимок не доказывает обход конкретного сервиса и не заменяет последующий HIL
YouTube TCP/googlevideo/QUIC. Он фиксирует только capability и ownership baseline.

## Автономность

`scripts/check-no-z2k-runtime.sh` и Windows-эквивалент блокируют URL загрузки
z2k в production tree, установщике и CI. Локальное чтение существующей установки
для preview/migration допускается, но RAZVILKA не устанавливает и не запускает
z2k и не зависит от его серверов.
