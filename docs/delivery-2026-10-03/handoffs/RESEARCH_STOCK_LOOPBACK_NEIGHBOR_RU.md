# Собственный IPv6-адрес моста в loopback neighbor dump

## Реальное наблюдение и граница исправления

ROOT diagnostic 336 на stock NC1812 прочитал полный dual-stack dump: 181 запись,
159 на выбранном ingress и 22 на остальных. Две ранее распознанные IPv4
служебные записи; отказов decoder нет. Единственный address conflict:
владелец `bridge_local`, кандидат на loopback с другим MAC и ingress;
IPv6 глобальный ключ, одинаковый адрес. GETLINK подтвердил `ARPHRD_LOOPBACK`
772 и `IFF_LOOPBACK`; запись имела NOARP 64, flags 0, RTN_LOCAL 2,
72 байта ndmsg, ровно атрибуты DST 16 / LLADDR zero6 / CACHEINFO 16 / PROBES 4.
Адреса, MAC, имена и пользовательские intent ID здесь не публикуются.
Это диагностическое наблюдение не предоставляет разрешения на Apply и
не заменяет часовую проверку приложения.

Private decoder для foreign ingress распознаёт только эту форму, при
совпадении IPv6 DST с **точным host address** одного выбранного моста из
kernel LinkAddresses. Принадлежность подсети недостаточна. Link-local,
IPv4, mapped, multicast, loopback/unspecified адреса, ненулевой/пустой MAC,
другой index/state/flags/type и изменённый набор или длины атрибутов не
получают исключение. Индекс 1 опирается на проверенный kernel invariant ниже;
нового публичного факта, разрешения или доверенного JSON поля не добавлено.

Capture использует свежие actual segments; multicast notification использует
segments исходного неизменяемого Snapshot. Предикат общий. Строгий decoder
выбранного ingress и поведение nil/lan_except сохранены. Конфликты адресов
выбранных/исключённых устройств, router negative и другого моста остаются
отказами. Служебные записи продолжают расходовать record/byte/startup bounds;
sticky отказ коллектора не сбрасывается и Review не переоткрывается.

## Первичные исходники проверенного ядра

Зафиксированная ревизия: `keenetic/kernel-49@7b6c9477`.

- [include/net/flow.h, строки 15–21](https://github.com/keenetic/kernel-49/blob/7b6c9477/include/net/flow.h#L15-L21): индекс loopback равен 1 в каждом network namespace.
- [drivers/net/loopback.c, строки 149–197](https://github.com/keenetic/kernel-49/blob/7b6c9477/drivers/net/loopback.c#L149-L197): единственный loopback на namespace, Ethernet addr_len 6, тип/флаг loopback; BUG_ON проверяет LOOPBACK_IFINDEX после регистрации.
- [net/ipv6/ndisc.c, строки 302–346](https://github.com/keenetic/kernel-49/blob/7b6c9477/net/ipv6/ndisc.c#L302-L346): loopback neighbor получает NOARP, адрес устройства и RTN_LOCAL.
- [net/core/neighbour.c, строки 2077–2120](https://github.com/keenetic/kernel-49/blob/7b6c9477/net/core/neighbour.c#L2077-L2120): neigh_fill_info формирует ndmsg, DST, LLADDR при NUD_VALID, PROBES и CACHEINFO; одинаковая wire форма для dump и notification.

## Проверка

Pure production-path fixtures проверяют capture и NEW/DEL notification на
одном исходном Review, forward и retained incarnation, неизменяемые факты,
отказ остальных форм, конфликты cohort/router, strict selected decoder,
4096 complete-dump records и 8192 pre-baseline datagrams.
Fixture не означает успешную native проверку или завершённый часовой тест.
Linux race/build и native read-only continuity 341 выполняет только ROOT;
часовой App Apply + реальные LAN/VLESS пробы + Stop дважды остаются отдельной
обязательной приёмкой.
