# Entware /opt: bounded storage preflight для OPS — 04.10.2026

Поручение координатора: объяснить отказ managed NFQWS на реальном Netcraze `/opt` UID/GID1001 mode0755 и подготовить ограниченный install preflight. Исследовательская база `f386a9a`; источник guard прочитан в интеграционной базе `327234bed3f2ce1ebce51e484b2b2d048c6a4be6`. Только документы и чтение официальных источников/сохранённых артефактов. Роутер, USB, VM, ownership, mount options, production source и runtime не изменялись; диагностический скрипт/испытания не запускались.

## Результат для текущего случая

**Guard оставлять. На подтверждённом EXT4 возможна отдельная single-inode preparation; текущий install остаётся blocked на UID1001.** `0755` даёт владельцу UID1001 право изменять namespace `/opt`; он может переименовать/заменить дочерний `lib`, даже если сам `lib` UID0. Исправлять только `/opt/lib` недостаточно.

Координатор наблюдал `/opt` UID/GID1001 mode0755, `/opt/lib` UID0 mode0755. Сохранённый `.review-local/router-inventory.json` отдельно подтверждает `/opt`1001, `/opt/bin`0, `/opt/etc`1001, `/opt/var`1001 и filesystem device `/dev/sda1`; `df` показывает USB mount под `/tmp/mnt/<volume>`. Сам `df` **не устанавливает fstype, mount options, SMB mapping или canonical path**.

Новое read-only уточнение координатора после подготовки отчёта: **`/dev/sda1 /opt ext4 rw,noatime,data=ordered`, свободно6.65GB**; `/opt/etc`, `/opt/tmp`, `/opt/var` UID1001, `/opt/bin`, `/opt/lib`, `/opt/home` UID0. UID1001 сопоставлен с `ndmp`/owner-admin, home `/tmp/mnt`. Это обычный EXT4 VFS ownership, не mount-wide fixed UID. Изменений ownership не было. Источник этого уточнения — сообщение координатора, не повторный запуск здесь; полная target share/ACL policy ещё не предоставлена.

Текущий [guard](C:/Projects/RAZVILKA/delivery-review/internal/components/nfqws_bundle_fs.go:26) проходит все canonical ancestors до `/`, требует UID0, other-execute, отсутствия group/other-write, symlink/special bits. [Linux owner check](C:/Projects/RAZVILKA/delivery-review/internal/components/nfqws_bundle_linux.go:55) **не требует GID0**: GID1001 при0755 сам по себе допустим. Production root фиксирован `/opt/lib/razvilka/nfqws2/releases`; `nfqwsReleases` — private test relocation, не готовая пользовательская настройка другого каталога.

## Что устанавливают официальные источники

- [Netcraze OPKG](https://support.netcraze.ru/giga/nc-1012/ru/18481-opkg.html) и [Keenetic OPKG](https://support.keenetic.com/peak/kn-2710/en/18481-opkg.html) требуют EXT для OPKG и рекомендуют EXT4. Установка компонента поддержки exFAT/FAT для файлового сервера не означает их пригодность для Entware executable storage.
- [Официальный Netcraze installer guide](https://support.netcraze.ru/giga/nc-1012/ru/20980-installing-the-entware-repository-on-a-usb-drive.html) показывает доступ через SMB для загрузки installer, затем mount USB-раздела в `/opt`. Следовательно, изменение ownership `/opt` может изменить **корень раздела**, а не отдельную папку программы. В прочитанных инструкциях нет рекомендации автоматически делать `chown -R` всего USB или обязательной расшифровки UID1001.
- [Entware standard/alternative](https://github.com/Entware/Entware/wiki/Alternative-install-vs-standard): alternative имеет отдельные persistent passwd/group, в отличие от standard firmware symlinks; Keenetic использует alternative. Проверять числовые UID/EUID, а не только имя `root`/`admin`: одинаковое имя в firmware/Entware не доказывает одинаковую numeric identity. Shadow/password hashes не нужны диагностике.
- [Netcraze folder access](https://support.netcraze.ru/giga/nc-1012/ru/18485-folder-permission-control-on-a-usb-drive.html) отдельно задаёт read/write/inherit для сетевых пользователей и требует чтение родителей для доступа к дочерним папкам. [SMB guide](https://support.netcraze.ru/giga/nc-1012/ru/19084-smb-server--shared-access-to-files-and-printers-.html) описывает anonymous access по умолчанию. POSIX metadata и effective share policy нужно проверять отдельно; эти статьи не доказывают, под каким Unix UID работает текущий SMB writer.

## Матрица filesystem

| Фактический driver/type | Значение для preflight |
|---|---|
| EXT4/EXT3/EXT2 | Owner/mode хранятся в inode: возможна смена UID **одного directory inode** с сохранением GID/mode и остальных файлов. Смена UID корня не исправляет чужие owners ниже. Не считать `uid=0` mount option способом исправления EXT4 inode. [EXT4 inode format](https://docs.kernel.org/filesystems/ext4/inodes.html). |
| VFAT/FAT | Нет on-disk Unix UID/GID; `uid/gid/umask/dmask/fmask` задаются mount-wide. Remount с UID0 меняет представление всего раздела и затрагивает сетевой доступ. `showexec` также может исключить исполнение Unix binary. Для этого managed payload — unsupported, без remount/chown retry. [Kernel VFAT](https://docs.kernel.org/filesystems/vfat.html). |
| exFAT | В официальном Linux v6.6 inode UID/GID берутся из mount options. `setattr` отвергает другой owner; некоторые недопустимые mode изменения молча игнорируются с success. У directory не гарантировано независимое sealing0555. **Exit0 chmod не является proof.** Текущий vendor/FUSE driver нужно назвать явно; upstream source не удостоверяет driver Netcraze. [inode.c](https://github.com/torvalds/linux/blob/v6.6/fs/exfat/inode.c#L508), [super.c](https://github.com/torvalds/linux/blob/v6.6/fs/exfat/super.c#L213), [file.c](https://github.com/torvalds/linux/blob/v6.6/fs/exfat/file.c#L229). |
| UBIFS | Возможный persistent POSIX candidate только на поддерживающей модели, при проверенных ancestors и read/write/durability capabilities. [Keenetic internal Entware](https://support.keenetic.com/titan/kn-1811/en/18482-installing-opkg-entware-in-the-router-s-internal-memory.html) описывает `/storage` → `/opt`, начиная с3.7 для некоторых моделей; поддержка на данном Netcraze не установлена. |
| tmpfs, squashfs/ro, network/FUSE/unknown | tmpfs не persistent, ro не writable; неизвестный/network/FUSE driver не получает capability из UID0/mode0755. Отказ либо отдельное принятие точного backend. Никакого автоматического fallback в `/tmp`. |

Managed generation сейчас требует separate0444 data/0555 binary+dirs, private0700 stage, file/directory Sync и Renameat2(RENAME_NOREPLACE), с повторным чтением дерева/owners/modes/hashes. Это шире права «можно создать файл»: [archive readback](C:/Projects/RAZVILKA/delivery-review/internal/components/nfqws_bundle_archive.go:270), [publication](C:/Projects/RAZVILKA/delivery-review/internal/components/nfqws_bundle_linux.go:17). Mount UID0 на FAT/exFAT этих semantics не добавляет.

## Предлагаемый read-only preflight

Один bounded native helper OPS в существующем install path **до download, mkdir и journal effect**. Это предложение API/диагностики, не уже реализованный endpoint.

1. Прочитать EUID/EGID и фиксированный intended root. `lstat /opt`, resolve только одобренного mount base; symlink ниже base запрещён. Проверить все существующие ancestors (лимит32); missing suffix не создавать. Записать path/type/dev/inode/numeric UID/GID/mode и **первую точную причину отказа**.
2. Прочитать `/proc/self/mountinfo` именно process namespace, bounded1MiB/2s. Определить top visible mount для пути, root внутри filesystem, source major:minor, fstype, per-mount и superblock flags; повторить после stat. [mountinfo format](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html). `df` или текст `bind` в options недостаточны; mount ID может переиспользоваться, поэтому не persistent identity. Неразбираемый/изменившийся mount — отказ.
3. Выдать readonly/exec/persistent/POSIX-modes/directory-sync/no-replace capabilities как supported/unsupported/unknown. Не создавать «пробный» файл под ещё недоверенным ancestor. File-operation readbacks выполняются только после admission в собственном staging обычной install transaction; ошибки не превращаются в ready receipt.
4. Отдельно прочитать доступную share/ACL metadata **для данного корня и alias**, включая firmware-created sharing и anonymous policy. Не считать отсутствие optional утилиты доказательством «share нет». Проверить, не доступен ли namespace сетевому root-backed writer. Не отключать SMB целиком и не менять пользовательские ACL автоматически.
5. Только при успешных storage prerequisites переходить к обычным authority/CAS/Stop/inactive guards и install. Root-owned storage не является правом запускать engine или изменять NFQUEUE.

Пример ответа по имеющимся данным:

```json
{
  "status": "blocked",
  "reason": "ROOT_OWNER_REQUIRED",
  "offending_path": "/opt",
  "observed": {"uid": 1001, "gid": 1001, "mode": "0755"},
  "filesystem": "ext4",
  "sharing": "unverified",
  "automatic_repair": false,
  "effects": []
}
```

Это proposed schema. Понятное сообщение: «Установка NFQWS2 остановлена: каталог /opt принадлежит UID1001. Права диска не изменены. Требуется проверить файловую систему и доступ к этому каталогу».

## Когда допустима ограниченная подготовка

Для подтверждённого сейчас EXT4 конкретный план: `/opt` — mount/real directory с проверенными ancestors,0755 без специальных bits/недопустимого ACL; владелец согласовал влияние на share. Отдельная явно авторизованная platform preparation меняет **только UID этого inode1001→0**, сохраняя GID1001 и mode0755. Для OPS — открыть/pin directory fd с проверкой mount/dev/inode, повторно сверить и сделать `fchown(fd,0,-1)`, затем Sync+readback identity/owner/mode и mount facts. [fchown semantics](https://man7.org/linux/man-pages/man2/chown.2.html). Не выполнять здесь; не включать как silent install repair.

Просматриваемый effect plan состоит из одной записи: `path=/opt; expected={UID1001,GID1001,mode0755,dev,inode,mount}; target={UID0,GID1001,mode0755}; descendants=none; mount_options=unchanged`. Для этого EXT4 случая remount не нужен. Пока отсутствуют одобрение этого действия и точные tuple/share facts, preflight возвращает план и blocked, без mutation. После согласованной подготовки — полный повтор существующего guard, отдельно inode/owner readback после штатного remount/reboot; persistent EXT4 inode не доказывает, что firmware никогда не перезапишет owner.

На native EXT изменение owner directory не переписывает children. Для локального UID1001 это убирает создание/удаление/rename top-level entries; существующие доступные subdirectories могут сохранять своё содержимое/owners. Effective SMB access зависит от его impersonation/ACL; подтвердить на существующем share после согласованной подготовки. Не менять GID или chmod только ради root:root. Не трогать `/opt/etc`, `/opt/var`, media, другие разделы, mount options и descendants; не объявлять всю Entware установку защищённой этим одним изменением. Если обнаружен следующий foreign ancestor — новый точный отказ, а не рекурсивное продолжение.

Если canonical `/opt` оказывается symlink в writable/sticky `/tmp`, нынешний guard также откажет на этом ancestor. **Не chmod/chown `/tmp` и не освобождать его из production guard.** Требуется подтверждённый firmware mount path, не непроверенный symlink/ручной bind. До получения mountinfo нельзя обещать, что single-inode preparation устранит все причины отказа.

Не откатывать owner к1001 автоматически после publication: это заново откроет namespace опубликованной generation. Platform preparation и её возможная отмена требуют отдельного рассмотрения отсутствия payload/runtime/receipts, не являются частью generic bundle-failure cleanup.

## Альтернативное persistent место

Наиболее простой вариант без изменения guard — **подтверждённый root-owned EXT раздел, выбранный firmware как `/opt`**, либо официально поддерживаемое внутреннее UBIFS, также mounted в `/opt`. Переключение OPKG disk меняет окружение всех Entware packages: нужна самостоятельная согласованная migration с сохранением прежнего диска/состояния; это не bounded NFQWS install fallback. Внутренний flash учитывать по модели, свободному месту, сохранению после boot/upgrade и directory Sync, без форматирования/erase.

Для payload отдельно на реально существующем root-owned persistent `/storage/...` нужен **новый явно назначенный OPS/CORE storage contract**: проверенный fixed mount base+relative path, identity/revalidation, одинаковая политика ancestors, receipt path и runtime resolver; все операции descriptor-anchored. Текущий private `nfqwsReleases` не публиковать как произвольный path override. Ссылки из чужого `/opt`, перенос в `/opt/var` или под `/opt/lib` при прежнем UID1001 родителе, ручной bind для обхода проверки, hash-before-exec через недоверенное место и copy в RAM — не подтверждённые persistent альтернативы.

Следующее необходимое действие координатора/OPS — сохранить EUID + точные lstat/canonical ancestor/dev/inode tuples + соответствующие mountinfo records + target share/ACL facts, затем отдельно принять **одну** UID-only platform preparation. Эти дополнительные read-only данные не требуют установки пакетов или изменения USB. До подготовки и guard readback текущий install остаётся blocked; полный `chown USB`, remount, filesystem repair/format и runtime проба не поручались и не выполнялись.

Проверка документа: pinned/tagged official kernel source и официальные Entware/Keenetic/Netcraze страницы прочитаны; локальные ссылки/source lines сверены. Это source-level предложение; native storage preparation и persistence/SMB acceptance не заявлены.
