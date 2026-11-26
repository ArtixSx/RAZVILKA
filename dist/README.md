# Результаты сборки

Здесь [build.sh](../build.sh) создаёт Linux-бинарники и `SHA256SUMS`.
Сами бинарники не хранятся в Git. Для обычной установки скачайте
[стабильный выпуск](https://github.com/ArtixSx/RAZVILKA/releases/latest)
и следуйте [инструкции](../README.md).

| Файл | Архитектура |
| --- | --- |
| `razvilka-linux-arm64` | AArch64 / ARM64 |
| `razvilka-linux-mips` | MIPS, big-endian, soft-float |
| `razvilka-linux-mipsle` | MIPSel, little-endian, soft-float |
| `razvilka-linux-amd64` | x86-64, Linux; разработка и испытания |
| `SHA256SUMS` | Контрольные суммы этих бинарников |

Из корня исходников сборка запускается командой:

```sh
./build.sh
```

В Entware-комплекте папка `dist` уже заполнена. Установщик выбирает бинарник
и сверяет его сумму; не удаляйте `SHA256SUMS` и не смешивайте файлы разных выпусков.
Архив GitHub «Source code» содержит исходники, а не готовый комплект.

[Что означают остальные файлы](../docs/FILES_RU.md) ·
[Правила версий](../docs/VERSIONING_RU.md).
