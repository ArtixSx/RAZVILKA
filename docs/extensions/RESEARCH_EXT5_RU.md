# Основания решений EXT5 — сверка 16 сентября 2026

Чужие проекты изучены как первичные источники, их installer не выполнялся. Это
не сравнительный тест стабильности в сети владельца RAZVILKA.

- Mihomo configurator существует: https://github.com/123jjck/mihomo-configurator .
  README описывает browser YAML generator и шаги DNS→Servers→Rules→Download,
  Router/OpenWRT preset и тесты. Его код и remote iframe не встроены; RAZVILKA
  использует собственную конвертацию нормализованного профиля. Возможности меньшие,
  зато не возникает второй владелец правил/подписок и отправка ключей наружу.
- https://wiki.metacubex.one/en/config/general/ — loopback/API, process mode off,
  DNS/TUN/provider permissions. В EXT5 controller не запускается, скачивание geodata
  отключено. Native test данной core-версии ещё необходим.
- https://wiki.metacubex.one/en/config/proxies/vless/ — поля TLS/Reality/flow,
  ws/gRPC/packet-encoding. Новые XHTTP/другие возможности upstream не приписываются
  текущему ограниченному parser RAZVILKA. Неподдержанное отклоняется.
- https://wiki.metacubex.one/en/config/proxies/tuic/ — TUIC5 UUID/password,
  sni/udp-relay-mode/congestion. Не все URI-поля приняты старым parser: формат/параметры
  требуют явного расширения и не будут выброшены ради успешного импорта.
- https://github.com/heiher/hev-socks5-tunnel/blob/2.17.1/conf/main.yml — точная
  схема Hev: interface/mtu/IPv4, socks5 loopback/udp и misc budgets, скрипты и daemon
  опциональны. Их не переносим. ICMP reply исключён, чтобы не подменять egress ping.
  Не доказаны ни производительность, ни наличие совместимого бинарника на роутере.
- https://github.com/nfqws/nfqws2-keenetic/blob/c77226bd384e047a3d97e3ab6f0ad8b46fc3c967/etc/nfqws2/nfqws2.conf
  — два встроенных примера TCP circular и QUIC fake скопированы как кандидаты с
  сохранённой MIT лицензией в docs/third-party/NFQWS_LICENSE. Не импортируем init,
  globallists или весь script. `MODE_AUTO` — не разрешение на облачный Lua.
- z2k/пакетные update принципы из UPDATE4 остаются: personal strategy namespace,
  неизменяемая публикация, локальная проверка, одна система управления. Сетевая
  синхронизация z2k/community в EXT5 НЕ включена и его runtime не установлен.

Исследование и схемы не заменяют HIL. Программа EXT5 не объявляет новые компоненты
лучше/быстрее и не меняет рабочий default на основании README.
