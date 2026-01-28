echo $(pwd)
./configure \
      HOST_CPPFLAGS="-I$(pwd)"                                \
      TARGET_CPPFLAGS="-I$(pwd)"                              \
        --with-platform=efi                                     \
        --with-utils=host                                       \
        --target=x86_64                                          \
        --with-grubdir=grub2                                    \
        --program-transform-name=s,grub,grub2,          \
        --disable-werror || ( cat config.log ; exit 1 )         

echo now type: make
