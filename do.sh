#! /bin/bash
dot_config_file_path=/lib/modules/`uname -r`/build/
echo "reuse $dot_config_file_path/.config"
cat $dot_config_file_path/.config | sed 's/^CONFIG_LOCALVERSION.*$/CONFIG_LOCALVERSION="hello"/' > .config
make olddefconfig
make bindeb-pkg


