# Cloudflare Provider: локальный ключ и mock registrar

## Цель блока

Исправленный WARP Configurator не должен получать приватный WireGuard-ключ от
случайного сайта и не должен отправлять собственный ключ наружу. Первый слой
PR-1.2 отделяет локальную криптографию от будущего сетевого адаптера.

## Реализовано

- новый X25519 private key создаётся локально через системный источник
  случайности;
- граница `RegistrationAPI` принимает только публичный ключ, явное принятие
  условий, версию условий и безопасные сведения о клиенте;
- server response содержит секретные device ID/access token только во внутренней
  модели и не сериализует их в JSON;
- peer key, assigned prefixes, публичные IP endpoints, порты, API schema и
  revision условий проходят строгую ограниченную проверку;
- будущий кандидат имеет честный статус `registered-unverified`: регистрация
  сама по себе не доказывает handshake, egress или доступность сервиса;
- JSON, `String`, форматированные ошибки и публичная модель не раскрывают
  private key, device ID и access token;
- отменённый контекст не вызывает API, а отсутствие явного принятия условий
  блокирует операцию до генерации и сети.
- проверенный mock-кандидат можно атомарно сохранить как неактивную запись
  `local-registration` в закрытом Provider Store. Этот kind нельзя подделать
  обычным публичным импортом; он сохраняется в зашифрованном private backup и
  после restore остаётся `registered-unverified`.
- типизированный внутренний `WithTunnelMaterial` выдаёт будущему изолированному
  builder только ключи, адреса и endpoints на время callback. Device ID и access
  token в этот scope не входят; backing-буферы очищаются после возврата, а
  JSON/логи всегда получают только redacted-маркер.

## Что намеренно отсутствует

- живой Cloudflare HTTP endpoint и знание его текущей схемы;
- экспорт WireGuard-конфига и transport builder;
- запуск интерфейса, изменение DNS/firewall/PBR или назначение сервису;
- AutoPilot и автоматическая ротация.

Эти части добавляются по очереди: golden fixtures/mock failures → bounded live
adapter → journaled candidate persistence → Endpoint Scanner → isolated canary.
Нельзя считать этот блок подтверждением работоспособности WARP у провайдера.

После сверки источников live consumer adapter оставлен закрытым. Схема
[wgcf](https://github.com/ViRb3/wgcf/blob/master/openapi-spec.yml) основана на
неофициально исследованном API, а upstream фиксировал случаи, когда регистрация
начала возвращать `500` после изменения Cloudflare
([issue #515](https://github.com/ViRb3/wgcf/issues/515)). Официальная документация
Cloudflare описывает административные Zero Trust registrations, но это не
обещание стабильности consumer endpoint. Поэтому текущий код знает только mock
контракт и не отправляет запросы на `api.cloudflareclient.com`.

## Проверки

- mock получает публичный ключ, но не private key;
- приватные данные отсутствуют во всех публичных представлениях;
- Terms/API/cancellation gates срабатывают до сети;
- отклоняются пустые токены, неверный peer key, приватный endpoint, дубликаты
  адресов и несовпадающая версия условий;
- WARP tunnel address в частном диапазоне разрешён как назначенный адрес, но
  endpoint сервера обязан быть публичным global-unicast IP.
- локальный candidate сохраняется идемпотентно, не может быть создан через
  публичный `ParseImport`, проходит encrypted backup preview/restore и после
  восстановления не становится активным.

Полный набор registrar и candidate-store тестов кросс-собран и выполнен на
ARM64 Keenetic: контрольная сумма совпала, положительные/отрицательные сценарии,
атомарное сохранение и encrypted backup/restore прошли. Тестовый бинарник
удалён; рабочая RAZVILKA осталась `0.18.0`, сеть и профили не изменялись.

Отдельный набор tunnel-material contract также выполнен на этом ARM64-роутере:
scope/redaction/очистка ключевых буферов, запрет capability для пассивного
импорта, cancellation и передача ошибки builder прошли. Временный бинарник
удалён, рабочий сервис не перезапускался.
