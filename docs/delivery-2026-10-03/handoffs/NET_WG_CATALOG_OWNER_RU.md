# NET D05: один каталог для runtime и API

Законченный подготовительный порт в `wg_profiles.go`:

`Manager.WireGuardProfileCatalog() (WireGuardProfileCatalog, error)` возвращает
каталог `Profiles` уже зарегистрированного actual `wireguard` адаптера. Интерфейс
включает Get/List/Put/Delete существующего `wireguardprofile.Store`; новый Store,
новый приватный путь и отдельный config CAS не создаются.

CORE trusted startup должен создать один Store и передать тот же указатель
адаптеру. NET новый HTTP handler получает именно этот порт. Отсутствующий Manager,
незарегистрированный actual adapter и provider только с Get дают конкретный отказ.

`TestWireGuardProfileCatalogUsesRegisteredRuntimeOwner` — PASS: catalog равен
исходному указателю, запись catalog сразу видна runtime; отсутствующий provider
отказан. Адресный прогон — 0.075s. Общий NET 5-package прогон на текущем рабочем
состоянии — PASS (dataplane 99.967s, DNS 2.390s); Win/Linux vet и Linux amd64
dataplane cross-compile — RC 0. Эти общие проверки также включали явно отдельный
WG network-policy WIP и не означают его native приёмку.

Порция содержит только этот порт, его тест и данный handoff. Это не завершение
D05: далее нужны auth/CSRF HTTP CRUD/reference/reserve, полный deletion fence под
существующей config file lease, CORE main/Handler registration и проверка обычного
app path. Автоматическое переключение на резерв данным портом не разрешается.
