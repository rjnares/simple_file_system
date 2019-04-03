# simple_file_system
Simple file system that stores up to 64 files on a virtual disk implemented using a file allocation table (FAT). This virtual disk is made up of 8192 blocks of size 4096 bytes each. The first half of the disk is reserved for disk and file meta-data (i.e. the super block, root directory, and file allocation table). The second half of the disk is reserved for file data. The disk can store a maximum of 64 files in 16 MB of space.  

The virtual disk provides a persistent storage, meaning data written onto disk is available after being remounted.
