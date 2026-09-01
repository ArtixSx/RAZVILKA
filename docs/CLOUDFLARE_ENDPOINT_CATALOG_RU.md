# Каталог WARP endpoints

1 сентября 2026 года · источник проверен по официальной документации Cloudflare.

RAZVILKA теперь не смешивает «endpoint выдал registrar» и «endpoint находится в
официально опубликованном диапазоне». Каталог только классифицирует уже выданный
адрес; он не генерирует и не подменяет endpoint.

Источник: [Cloudflare One Client with firewall](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/),
версия данных в коде — `cloudflare-firewall-2026-07-24`.

## WireGuard

- consumer IPv4: `162.159.192.0/24` — документация отдельно отмечает этот
  диапазон для consumer WARP до входа в организацию;
- Zero Trust IPv4: `162.159.193.0/24`;
- Zero Trust IPv6: `2606:4700:100::/48`;
- default: UDP `2408`;
- fallback: UDP `500`, `1701`, `4500`.

Старый consumer IPv6 `2606:4700:d0::/48`, встречающийся в сторонних генераторах,
в текущей официальной таблице не указан. Если registrar сам вернул такой адрес,
он сохраняется как `registrar-issued-unverified` и может пройти будущий
изолированный scan, но UI не должен называть его официальным или рекомендуемым.

Официальный диапазон с неизвестным портом и официальный порт с неизвестным
адресом также не получают `recommended=true`. Candidate fingerprint включает
версию и классификацию каталога, поэтому обновление сведений создаст новую
identity и потребует новый scan.

Каталог и его интеграция в candidate builder проверены на ARM64 Keenetic:
consumer/Zero Trust IPv4/IPv6, default/fallback/unknown ports, undocumented IPv6
и неизменяемая копия списка портов прошли. Временный бинарник удалён; рабочая
RAZVILKA осталась `0.18.0`.
