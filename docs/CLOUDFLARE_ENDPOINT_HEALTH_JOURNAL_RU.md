# Приватный журнал Cloudflare Endpoint Health

Журнал сохраняет только локальный результат Scanner: TTL, score, cooldown и
идентичность проверенного кандидата. В нём нет WireGuard private key, access
token, device ID или пригодного для запуска конфига.

## Границы доверия

- запись возможна только из внутреннего `ScanReport`; JSON-копия отчёта теряет
  закрытый proof и не принимается;
- перед записью Provider заново читает текущий локальный account snapshot под
  тем же process/OS writer lock;
- route identity включает digest приватного snapshot. Смена ключа или материала
  при сохранённом account ID не наследует старый PASS;
- при чтении кандидат снова строится из текущего snapshot. Совпасть должны
  account, digest, endpoint, catalog, MTU, keepalive и полный `RoutePathID`;
- истёкшая запись доступна только для диагностики и никогда не selectable;
- health не входит в переносимый backup: после restore на другом устройстве или
  в другой сети endpoint должен быть проверен заново.

## Хранение и восстановление

Файл `endpoint-health.private.json` находится в закрытом Provider root и имеет
режим `0600` на Linux. Документ содержит schema, owner, generation и ограниченное
число записей. Неизвестные поля, неверная schema, duplicate identity, слишком
большой файл, небезопасные права, symlink или противоречивые timestamps приводят
к fail-closed ошибке; пустые значения не подставляются.

Commit выполняется через временный файл, `fsync`, atomic rename и directory sync
на Linux. Account snapshot и журнал используют одну `.import.lock`, поэтому
import/restore не может заменить аккаунт между проверкой identity и commit.
Ошибка после rename считается неопределённым результатом записи; следующий
startup обязан перечитать точный файл и не продолжает с догадкой.

`ScanAndRecord` — будущая рабочая точка входа: положительный endpoint становится
доступен после durable commit, отрицательный результат сохраняет cooldown.
Реального сетевого runner и пользовательского переключателя пока нет; журнал не
повышает inert candidate до работающего маршрута самостоятельно.

## ARM64 gate

На целевом Keenetic ARM64 прошли restart/TTL, changed identity, forged report,
unknown/corrupt document, cooldown persistence, `ScanAndRecord` и новый material
binding кандидата. SHA-256 теста совпал; временный бинарник удалён. Установленная
RAZVILKA осталась `0.18.0`, её процессы и сетевые настройки не изменялись.
