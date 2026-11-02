# Выделения временных буферов NFQWS2

Сопоставлены два завершённых реальных native core сценария с одинаковым числом чтений, проверок, дочерних процессов и обходов metadata. Это одна пара запусков GitHub Ubuntu/Go 1.26.5, а не статистика p50/p95. Исходные commits, jobs, SHA256 полных журналов и точные счётчики — в [results.json](results.json); выдержки сохранены без изменения строк.

| Метрика | До (2b0a8df1) | После (a24fac4f) |
| --- | ---: | ---: |
| Суммарно выделено Go, байт | 3 530 642 792 | 2 129 950 744 |
| Число выделений | 8 236 156 | 8 234 076 |
| Execute wall, с | 9,900057282 | 11,197411115 |

Снижение накопленного объёма выделений на 39,67% не означает такое же снижение RSS или потребления RAM. Время этой пары выросло: ускорение не подтверждено. До/после выполнены 13 260 member reads (1 084 270 200 байт), 382 ToolCheck, версии iptables/ip6tables/IP запущены 175/175/386 раз, 2360 metadata traversals. Каждый source/kernel read остаётся настоящим. Лимит proc-чтения сохранён, но начальная ёмкость ограничена 4096 байт; netlink использует эксклюзивный временный буфер и клонирует возвращаемые сообщения.

Отдельный локальный микротест полного SHA256 retained FD на Windows/Ryzen 7800X3D/Go 1.26 (N=5, по 1 с) проверяет замену отдельной 32KiB allocation на эксклюзивный sync.Pool scratch. Для 32KiB медиана 23044→18984 ns/op, 32834→33 B/op, 3→2 allocs/op; для 1MiB медиана 585531→541765 ns/op. Сырые [до](hash-buffer-before.txt) и [после](hash-buffer-after.txt) сохранены. Удалены только конечные пробелы в строках CPU; значения не изменены. Это не измерение полного VLESS/LAN пути.

[Native run](https://github.com/ArtixSx/RAZVILKA/actions/runs/41409748096): normal/race actual-FD границы размера/EOF, concurrent fresh hash и ошибки, настоящие netlink dumps с независимыми payload PASS. Исходные mutation gates также PASS; полный LAN manual и race workflow пока FAIL по deadline. [Полный CI a24fac4f](https://github.com/ArtixSx/RAZVILKA/actions/runs/41409748122) SUCCESS. Роутер этим не проверен.
