make clean
cp -f bpf-next-kernel-config-trimmed.txt /usr/src/bpf-next/.config
yes "" | make oldconfig
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
time make -j 8 bzImage
time make -j 8 modules
time make -j 8
make headers
cd tools/testing/selftests/bpf; make

