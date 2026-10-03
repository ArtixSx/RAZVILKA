# D06 — prerequisite для отдельной Linux VM координатора

Команды ниже **не запускались NET**. Они предназначены только координатору для принадлежащей ему exclusive Ubuntu26.04 VM. На Netcraze `4.9-ndm-5 arm64` эти команды и namespace harness не переносить: ABI/firmware и отсутствие PID/netnamespace требуют отдельного HIL-плана. Успех VM не является router acceptance.

## Проверенные официальные pins

- [amneziawg-tools v3.1.20260812](https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v3.1.20260812): `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`.
- [amneziawg-linux-kernel-module v3.1.20260906](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/tree/4569c4c67f3a57414969260cafbbd04694fbaae0): `4569c4c67f3a57414969260cafbbd04694fbaae0`.

Оба pins проверены по официальным `git ls-remote refs/tags/...`. Не использовать moving master, неофициальный бинарник или userspace backend для kernel ABI acceptance. CLI сообщает `amneziawg-tools v3.1.20260812 - https://amnezia.org`, согласно [wg.c этого тега](https://raw.githubusercontent.com/amnezia-vpn/amneziawg-tools/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/wg.c).

В [Makefile kmod](https://raw.githubusercontent.com/amnezia-vpn/amneziawg-linux-kernel-module/4569c4c67f3a57414969260cafbbd04694fbaae0/src/Makefile) default `WIREGUARD_VERSION=1.0.0`; его нужно задать явно при сборке и module-install. [version.h](https://raw.githubusercontent.com/amnezia-vpn/amneziawg-linux-kernel-module/4569c4c67f3a57414969260cafbbd04694fbaae0/src/version.h) отдельно содержит fallback `3.1.20260812`. Версия тега и надпись версии сами по себе не доказательство kernel/module/CLI совместимости. Связь loaded module с установленным metadata проверяется по srcversion, version, initstate, vermagic текущего ядра и отсутствию forced load/unload.

## Подготовка sources и сборка, без смены kernel

Запускать последовательно в shell координатора, останавливаясь на первой ошибке. Точное значение kernel берётся из `uname -r`, включая suffix, а не из сокращённого `7.0.0-34`. Сборка pinned source на этом ядре пока **unverified**; compile error не обходить отключением диагностики или force load.

```sh
set -eu
awg_kernel=$(uname -r)
uname -m
cat /proc/version
sudo apt-get update
sudo apt-get install -y build-essential git kmod pkg-config libmnl-dev libelf-dev "linux-headers-$awg_kernel" iproute2 wireguard-tools
test -d "/lib/modules/$awg_kernel/build"

# Новый отдельный каталог внутри test-owned workspace.
awg_build_root="$PWD/native-awg-source-20261003"
test ! -e "$awg_build_root"
mkdir -m 700 "$awg_build_root"
git clone --depth 1 --branch v3.1.20260812 https://github.com/amnezia-vpn/amneziawg-tools.git "$awg_build_root/tools"
git clone --depth 1 --branch v3.1.20260906 https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$awg_build_root/module"
test "$(git -C "$awg_build_root/tools" rev-parse HEAD)" = ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
test "$(git -C "$awg_build_root/module" rev-parse HEAD)" = 4569c4c67f3a57414969260cafbbd04694fbaae0
make -j2 -C "$awg_build_root/tools/src"
make -j2 -C "$awg_build_root/module/src" KERNELRELEASE="$awg_kernel" KERNELDIR="/lib/modules/$awg_kernel/build" WIREGUARD_VERSION=3.1.20260906
"$awg_build_root/tools/src/awg" --version
modinfo "$awg_build_root/module/src/amneziawg.ko"
sha256sum "$awg_build_root/tools/src/awg" "$awg_build_root/module/src/amneziawg.ko"
```

## Установка/load только после успешной сборки в exclusive VM

Эта часть меняет VM, поэтому исполняет только координатор. При уже загруженном amneziawg условие ниже остановит последовательность: не заменять неизвестный живой модуль и не выполнять rmmod/insmod -f. Никакого reboot в recipe нет. Если Secure Boot отвергает неподписанный модуль, это отдельный prerequisite, а не разрешение force load.

```sh
test ! -e /sys/module/amneziawg
sudo make -C "$awg_build_root/module/src" module-install KERNELRELEASE="$awg_kernel" KERNELDIR="/lib/modules/$awg_kernel/build" WIREGUARD_VERSION=3.1.20260906
sudo modprobe amneziawg
modinfo amneziawg
cat /proc/sys/kernel/osrelease /proc/sys/kernel/tainted
cat /sys/module/amneziawg/version /sys/module/amneziawg/srcversion /sys/module/amneziawg/initstate /sys/module/amneziawg/taint
```

Missing/old/unknown/wrong ABI module считается отказом admission, не PASS native. `O/E` (out-of-tree/unsigned) не равны forced-load `F`; forced-load/unload bits2/8 kernel taint и module F/R отклоняются. Основание: [официальная документация kernel taint](https://docs.kernel.org/admin-guide/tainted-kernels.html).

## Native команды после интеграции NET D06

Оставить общий AppArmor-approved TMPDIR и установленный Go1.26.5. Перед запуском не наследовать `RAZVILKA_WG_NATIVE_ROLE/ROOT/READY/RECOVER_ROOT/ENDPOINT/NOW/TEST_ENDPOINT/SERVER_NS`. Source root выше должен остаться читаемым namespace children; CLI устанавливать в /usr для теста необязательно: передаётся его exact absolute path.

```sh
RAZVILKA_AWG_NATIVE=1 RAZVILKA_AWG_NATIVE_TOOL="$awg_build_root/tools/src/awg" GOMAXPROCS=2 GOFLAGS=-p=2 go test ./internal/awgprofile -run '^TestAWGNativeCompatibilityReceipt$' -count=1 -v -timeout=30s
sudo env RAZVILKA_AWG_NATIVE=1 RAZVILKA_AWG_NATIVE_TOOL="$awg_build_root/tools/src/awg" TMPDIR="$TMPDIR" GOMAXPROCS=2 GOFLAGS=-p=2 go test ./internal/dataplane -run '^TestAWG31NativeCandidateIsolation$' -count=1 -v -timeout=4m
```

Второй тест требует root + Linux netns/veth и уже загруженный совместимый module. Создаёт только свои namespaces/порты; в них два kernel AWG3.1 servers с HeaderProtectionKey/S1–S4/H1–H4/RandomTrailers, независимые client identities, IPv4/IPv6 payload TCP/UDP. Проверяет same-key safe rejection, positive candidate, wrong peer rejection, live-after каждой ветви, foreign route preservation и отсутствие temporary interface/table219. Он не закрывает LAN default executor, reboot, hardware acceptance или rollback addition receipt.
