# Разовая проверка импортированного WARP WireGuard-профиля

2 сентября 2026 года · локальный блок Unified Cloudflare Provider.

Обычный импорт в «Копии аккаунтов Cloudflare» остаётся пассивным архивом и не
получает право запуска. Для будущей команды «Проверить этот профиль» добавлен
отдельный ephemeral-контракт: вызывающая сторона должна получить самостоятельное
подтверждение пользователя, передать исходный файл только на время операции и
не сохранять результат как рабочий маршрут.

## Что принимается

- один строгий `[Interface]` и один `[Peer]` без hooks и неизвестных полей;
- корректные X25519 private/public keys;
- IPv4 tunnel address и полный `AllowedIPs = 0.0.0.0/0` (опционально `::/0`);
- публичный IP-literal endpoint с допустимым портом;
- bounded MTU/keepalive, которые Scanner всё равно нормализует безопасными
  параметрами кандидата.

Hostname endpoint пока отклоняется: DNS discovery и привязка ответа к текущей
сети должны стать отдельным проверяемым этапом, а не скрытой догадкой. Также
отклоняются private/loopback/link-local endpoints, PSK, частичные AllowedIPs,
NUL, oversized input и отменённая операция.

## Граница доверия

- профиль не записывается в Provider Store и health journal;
- passive import не повышается до runnable автоматически;
- ключи доступны только внутри callback и затираются после него;
- публичный preview содержит лишь derived identity и параметры;
- Scanner всё равно требует две полные попытки с handshake, новым egress,
  `warp=on`, exact service evidence, MTU и подтверждённым cleanup;
- PASS разовой проверки не включает Apply/AUTO. Для постоянного использования
  потребуется отдельное осознанное promotion с новым durability/recovery gate.

Runner дополнительно проверяет, что IPv4 tunnel address не используется другим
интерфейсом роутера. Конфликт прекращает попытку до создания `rz-cf-scan`.

## Проверка

Полный Go test/vet прошёл. На Keenetic ARM64 выполнены позитивный ephemeral
candidate, стирание ключей, bounded Scanner `2/2`, отказ без подтверждения,
hostname/private endpoint/PSK/partial route/NUL/oversize и конфликт локального
адреса. Это unit/platform gate с детерминированными системными адаптерами, не
live Cloudflare HIL. Установленная версия осталась `0.18.0`; `rz-cf-scan` и table
`220` после теста отсутствовали, временные бинарники удалены.
