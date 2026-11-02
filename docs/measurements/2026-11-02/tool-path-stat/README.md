# Свежая проверка metadata пути инструмента

[Actual Linux job](https://github.com/ArtixSx/RAZVILKA/actions/runs/41444434457/job/125273920291): парный benchmark одного процесса, реальный root-owned `/usr/bin/env`, каждое обращение заново вызывает Lstat. Три повтора: FileInfo1645–1650нс/224B/2alloc → direct stat1453–1459нс/16B/1alloc. Full CI05613c82 SUCCESS; Linux tests сравнивают прежний результат и поля владельца/идентичности/времени.

Никакие metadata, byte hashes или результаты проверок не кешируются. Оба полных обхода, symlink/absence/extension checks сохранены. Полный native NFQWS2 LAN Apply всё ещё FAIL около16.1с; микрозамер не доказывает завершённый маршрут или ускорение полного workflow.
