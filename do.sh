#! /bin/bash
apt update
apt install -y bison flex libssl-dev vim make linux-headers-`uname -r` dpkg-dev libelf-dev bc cpio kmod rsync debhelper zstd
dot_config_file_path=/lib/modules/`uname -r`/build/
echo "reuse $dot_config_file_path/.config"
cat $dot_config_file_path/.config | sed 's/^CONFIG_LOCALVERSION.*$/CONFIG_LOCALVERSION="hello"/' > .config
make olddefconfig
make -j88 bindeb-pkg

#cat .config | grep CONFIG | sed 's/^\(.*\)CONFIG\(.*\)$/\1#define CONFIG\2/g' > linux-kernel-config.h
