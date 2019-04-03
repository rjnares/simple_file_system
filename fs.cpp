#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "disk.h"

#define FILE_SIZE_LIM 4096 * 4096
#define TOTAL_DATA_BLOCK_LIM 4096
#define FILE_NAME_LEN_LIM 15
#define NUM_FILE_LIM 64
#define UNASSIGNED -1
#define FD_LIM 32

int make_fs(char *disk_name);
int mount_fs(char *disk_name);
int umount_fs(char *disk_name);

int fs_open(char *name);
int fs_close(int fildes);
int fs_create(char *name);
int fs_delete(char *name);
int fs_read(int fildes, void *buf, size_t nbyte);
int fs_write(int fildes, void *buf, size_t nbyte);
int fs_get_filesize(int fildes);
int fs_lseek(int fildes, off_t offset);
int fs_truncate(int fildes, off_t length);

int get_free_block(int current_block, int dir_index);
int get_fd(unsigned short int dir_index);
int dir_file(char *name);
int get_next_block(unsigned short int current_block);

typedef struct {
    char file_name[FILE_NAME_LEN_LIM];
    unsigned int file_size;
    int first_block_num;
    unsigned short int total_blocks;
    unsigned short int total_fds;
    bool busy;
} dir_entry;

typedef struct {
    unsigned short int dir_start_block;
    unsigned short int dir_size;
    unsigned short int fat_start_block;
    unsigned short int fat_total_blocks;
    unsigned short int data_start_block;
    unsigned int total_data_storage;
    unsigned short int avail_data_blocks;
} super_block;

typedef struct {
    unsigned int offset = 0;
    char file_name[FILE_NAME_LEN_LIM];
    int file_start_block = UNASSIGNED;
    bool busy = false;
    unsigned short int dir_index;
} file_descriptor;

typedef struct {
    bool busy = false;
    short int next = UNASSIGNED;
} fat_entry;


static fat_entry *fat;
static super_block *sb;
static dir_entry *dir;
static file_descriptor fds[FD_LIM];

int make_fs(char *disk_name) {
    if (make_disk(disk_name) == -1) return -1;
    if (open_disk(disk_name) == -1) return -1;
    
    fat = (fat_entry*)malloc(DISK_BLOCKS * sizeof(fat_entry));
    if (fat == NULL) return -1;

    fat[0].busy = true;

    /* 
     * could simplify by knowing that each fat_entry is 4 bytes so total fat bytes
     * is 4 * 8192 = 32,768 which equals 32,768 / 4096 = 8 blocks
     */
    char buf[BLOCK_SIZE];
    unsigned short int num_full_block_copies = (DISK_BLOCKS * sizeof(fat_entry)) / BLOCK_SIZE;
    unsigned int remainder_bytes = (DISK_BLOCKS * sizeof(fat_entry)) % BLOCK_SIZE;
    char *start_copy_from = (char*)fat;
    unsigned short int write_block = 1;
    unsigned short int num_fat_blocks = 0;
    for (unsigned short int i = 0; i < num_full_block_copies; ++i) {
        fat[write_block].busy = true;
        if ((i == (num_full_block_copies - 1)) && (remainder_bytes == 0)) break;
        else fat[write_block].next = ++write_block;
    }
    if (remainder_bytes != 0) fat[write_block].busy = true;
    write_block = 1;
    for (unsigned short int i = 0; i < num_full_block_copies; ++i) {
        memset(buf, 0, BLOCK_SIZE);
        memcpy(buf, start_copy_from, BLOCK_SIZE);
        block_write(write_block++, buf);
        ++num_fat_blocks;
        start_copy_from += BLOCK_SIZE;
    }
    if (remainder_bytes != 0) {
        memset(buf, 0, BLOCK_SIZE);
        memcpy(buf, start_copy_from, remainder_bytes);
        block_write(write_block++, buf);
        ++num_fat_blocks;
    }

    sb = (super_block*)malloc(sizeof(super_block));
    if (sb == NULL) return -1;
    
    sb->dir_start_block = write_block;
    sb->dir_size = 0;
    sb->fat_start_block = 1;
    sb->fat_total_blocks = num_fat_blocks;
    sb->data_start_block = 4096;
    sb->total_data_storage = 0;
    sb->avail_data_blocks = 4096;

    memset(buf, 0, BLOCK_SIZE);
    memcpy(buf, sb, sizeof(super_block));
    block_write(0, buf);

    free(sb);
    free(fat);
    close_disk();

    return 0;
}

int mount_fs(char *disk_name) {
    if (open_disk(disk_name) == -1) return -1;

    sb = (super_block*)malloc(sizeof(super_block));
    if (sb == NULL) return -1;
        
    char buf[BLOCK_SIZE];
    memset(buf, 0, BLOCK_SIZE);
    block_read(0, buf);
    memcpy(sb, buf, sizeof(super_block));

    fat = (fat_entry*)malloc(DISK_BLOCKS * sizeof(fat_entry));
    if (fat == NULL) return -1;

    // at this point we know it goes evenly, so no remainder calculation needed
    char *start_copy_from = (char*)fat;
    unsigned short int fat_start = sb->fat_start_block;
    for (int i = 0; i < sb->fat_total_blocks; ++i) {
        memset(buf, 0, BLOCK_SIZE);
        block_read(fat_start++, buf);
        memcpy(start_copy_from, buf, BLOCK_SIZE);
        start_copy_from += BLOCK_SIZE;
    }

    dir = (dir_entry*)malloc(sb->dir_size * sizeof(dir_entry));
    if (dir == NULL) return -1;


    unsigned short int num_full_block_copies = (sb->dir_size * sizeof(dir_entry)) / BLOCK_SIZE;   
    unsigned int remainder_bytes = (sb->dir_size * sizeof(dir_entry)) % BLOCK_SIZE;
    start_copy_from = (char*)dir;
    unsigned short int dir_block_copy = sb->dir_start_block;
   
    // printf("JUST CHECKING\n");
    // printf("FS1 FILES: %d\n", sb->dir_size);
    // printf("FULL COPIES: %d\n", num_full_block_copies);
    // printf("REMAINDER BYTES: %d\n", remainder_bytes);
    // printf("DIR START BLOCK: %d\n", dir_block_copy);
   
    for (unsigned short int i = 0; i < num_full_block_copies; ++i) {
        //if (fat[dir_block_copy].busy == false) return -1;
        memset(buf, 0, BLOCK_SIZE);
        block_read(dir_block_copy, buf);
        memcpy(start_copy_from, buf, BLOCK_SIZE);
        dir_block_copy = fat[dir_block_copy].next;
        if ((dir_block_copy == UNASSIGNED) && (remainder_bytes == 0)) break;
        start_copy_from += BLOCK_SIZE;
    }
    if ((dir_block_copy != UNASSIGNED) && (remainder_bytes != 0)) {
        //if ((fat[dir_block_copy].busy == false) || (fat[dir_block_copy].next != UNASSIGNED)) return -1;
        memset(buf, 0, BLOCK_SIZE);
        block_read(dir_block_copy, buf);
        memcpy(start_copy_from, buf, remainder_bytes);
    }
    
    for (int i = 0; i < FD_LIM; ++i) {
        fds[i].offset = 0;
        memset(fds[i].file_name, '\0', FILE_NAME_LEN_LIM);
        fds[i].file_start_block = UNASSIGNED;
        fds[i].busy = false;
    }

    return 0;
} 

int umount_fs(char *disk_name) {
    if (!disk_name) return -1;
    
    char buf[BLOCK_SIZE];
    unsigned short int num_full_block_copies = (sb->dir_size * sizeof(dir_entry)) / BLOCK_SIZE;

    
    unsigned int remainder_bytes = (sb->dir_size * sizeof(dir_entry)) % BLOCK_SIZE;

    
    char *start_copy_from = (char*)dir;
    unsigned short int dir_block_copy = sb->dir_start_block;

    
    for (unsigned short int i = 0; i < num_full_block_copies; ++i) {
      //if (fat[dir_block_copy].busy == false) return -1;
        //memset(buf, 0, BLOCK_SIZE);
        memcpy(buf, start_copy_from, BLOCK_SIZE);
        block_write(dir_block_copy, buf);
        //dir_block_copy = fat[dir_block_copy].next;
	++dir_block_copy;
	//if ((dir_block_copy == UNASSIGNED) && (remainder_bytes == 0)) break;
        start_copy_from += BLOCK_SIZE;
    }


    
    if ((dir_block_copy != UNASSIGNED) && (remainder_bytes != 0)) {
      //if ((fat[dir_block_copy].busy == false) || (fat[dir_block_copy].next != UNASSIGNED)) return -1;
	block_read(dir_block_copy, buf);
	//memset(buf, 0, BLOCK_SIZE);
        memcpy(buf, start_copy_from, remainder_bytes);
        block_write(dir_block_copy, buf);
    }

    start_copy_from = (char*)fat;
    unsigned short int fat_start = sb->fat_start_block;
    for (int i = 0; i < sb->fat_total_blocks; ++i) {
        //memset(buf, 0, BLOCK_SIZE);
        memcpy(buf, start_copy_from, BLOCK_SIZE);
        block_write(fat_start++, buf);
        start_copy_from += BLOCK_SIZE;
    }

    memset(buf, 0, BLOCK_SIZE);
    memcpy(buf, sb, sizeof(super_block));
    block_write(0, buf);

    for (int i = 0; i < FD_LIM; ++i) {
        fds[i].offset = 0;
        memset(fds[i].file_name, '\0', FILE_NAME_LEN_LIM);
        fds[i].file_start_block = UNASSIGNED;
        fds[i].busy = false;
    }

    //printf("FILE NAME FROM UMOUNT: %s\n", dir[0].file_name);


    free(sb);
    free(dir);
    free(fat);

    close_disk();
    

    return 0;
}

int fs_open(char *name) {
    if (!name) return -1;

    // printf("FIRST BLOCK: %d\n", dir[0].first_block_num);
    // printf("TOTAL BLOCKS: %d\n", dir[0].total_blocks);
    // printf("TOTAL FDS: %d\n", dir[0].total_fds);
    // printf("FILE SIZE: %d\n", dir[0].file_size);
    // printf("FILE NAME: %s\n", dir[0].file_name);


    int dir_index = dir_file(name);
 
  //  printf("DIR_INDEX: %d\n", dir_index);
 
 
    if (dir_index == -1) return -1;    
    
    int fd = get_fd(dir_index);
    if (fd == -1) return -1;

    dir[dir_index].total_fds++;

    return fd;
}

int fs_close(int fildes) {
    if ((fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;

    int dir_index = fds[fildes].dir_index;
    fds[fildes].busy = false;
    dir[dir_index].total_fds--;

    return 0;
}

int fs_create(char *name) {
  if ((sb->dir_size + 1) > NUM_FILE_LIM) return -1;
  if ((strlen(name) <= 0) || (strlen(name) > FILE_NAME_LEN_LIM)) return -1;
  
  int dir_index = dir_file(name);  
  if (dir_index != -1) return -1;

  sb->dir_size++;
  dir_entry *new_dir_ptr = (dir_entry*)realloc(dir, sb->dir_size * sizeof(dir_entry));
  if (new_dir_ptr == NULL) return -1;
  
  dir = new_dir_ptr;
  
  dir_entry new_entry;
  new_entry.busy = true;
  strcpy(new_entry.file_name, name);
  new_entry.file_size = 0;
  new_entry.first_block_num = UNASSIGNED;
  new_entry.total_blocks = 0;
  new_entry.total_fds = 0;

  dir[sb->dir_size - 1] = new_entry;
  
  return 0;
}

int fs_delete(char *name) {
    int dir_index = dir_file(name);
    if (dir_index == -1) return -1;

    if (dir[dir_index].total_fds != 0) return -1;

    unsigned short int block_num = dir[dir_index].first_block_num;
    while (block_num != UNASSIGNED) {
        fat[block_num].busy = false;
        unsigned short int next = fat[block_num].next;
        fat[block_num].next = UNASSIGNED;
        block_num = next;
    }

    sb->avail_data_blocks += dir[dir_index].total_blocks;
    sb->total_data_storage -= dir[dir_index].file_size;

    dir_entry *new_dir = (dir_entry*)malloc((sb->dir_size - 1) * sizeof(dir_entry));
    if (new_dir == NULL) return -1;

    unsigned short int new_dir_index;
    unsigned short int old_dir_index;
    for (old_dir_index = 0; old_dir_index < sb->dir_size; ++old_dir_index) {
        if (strcmp(dir[old_dir_index].file_name, name) != 0) new_dir[new_dir_index++] = dir[old_dir_index]; 
    }
    free(dir);
    dir = new_dir;
    sb->dir_size--;

    return 0;
}

int fs_read(int fildes, void *buf, size_t nbyte) {
    if ((nbyte <= 0) || (fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;    
    
    int dir_index = fds[fildes].dir_index;    
    size_t readable_bytes = dir[dir_index].file_size - fds[fildes].offset;    
    size_t limit;
    if (readable_bytes < nbyte) {
        limit = readable_bytes;
    } else {
        limit = nbyte;
    }


    char read_block[BLOCK_SIZE];
    char *temp_buf = (char*)malloc(limit);
    char *temp_buf_ptr = temp_buf;
    char *start_copy_from;
    size_t num_bytes_read = 0;
    unsigned int counter = fds[fildes].offset;

    
    int curr_block = dir[dir_index].first_block_num;


    
    while (counter >= BLOCK_SIZE) {
        curr_block = get_next_block(curr_block);
        if (curr_block == -1) return -1;

        counter -= BLOCK_SIZE;
    }

    
    
    block_read(curr_block, read_block);
    start_copy_from = read_block + counter;

    if ((limit + counter) < BLOCK_SIZE) {
        num_bytes_read = limit;
    } else {
      num_bytes_read = BLOCK_SIZE - (size_t)counter;
    }


    
    memcpy(temp_buf_ptr, start_copy_from, num_bytes_read);
    temp_buf_ptr += num_bytes_read;
    readable_bytes = limit - num_bytes_read;


    
    while ((num_bytes_read < limit) && (fat[dir_index].next != UNASSIGNED)) {


      curr_block = get_next_block(curr_block);
      
        if (curr_block == -1) return -1;

	block_read(curr_block, read_block);

	
        if (readable_bytes < BLOCK_SIZE) {

	  
	  memcpy(temp_buf_ptr, read_block, readable_bytes);
            temp_buf_ptr += readable_bytes;
            num_bytes_read += readable_bytes;

	    
        } else {


	  memcpy(temp_buf_ptr, read_block, BLOCK_SIZE);
	  temp_buf_ptr += BLOCK_SIZE;
	  readable_bytes -= BLOCK_SIZE;
	  num_bytes_read += BLOCK_SIZE;
        }
    }
    fds[fildes].offset += num_bytes_read;
    memcpy(buf, temp_buf, limit);
    free(temp_buf);
    return num_bytes_read;
}

int fs_write(int fildes, void *buf, size_t nbyte) {
    if ((nbyte <= 0) || (fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;

    char *buf_ptr = static_cast<char*>(buf);
    char temp_buf[BLOCK_SIZE];
    int dir_index = fds[fildes].dir_index;    
    int curr_block = dir[dir_index].first_block_num;
    
    unsigned int counter = fds[fildes].offset;
    size_t num_bytes_written = 0;
    char *start_writing_from;
    unsigned short int block_offset = 0;
    while (counter >= BLOCK_SIZE) {
        curr_block = get_next_block(curr_block);
        if (curr_block == -1) return -1;

        counter -= BLOCK_SIZE;
        ++block_offset;
    }
    
    if (curr_block != -1) {
      block_read(curr_block, temp_buf);    
      for (unsigned short int i = counter; i < BLOCK_SIZE; ++i) {
        temp_buf[i] = buf_ptr[num_bytes_written++];
        if (num_bytes_written == nbyte) {
	  block_write(curr_block, temp_buf);
	  fds[fildes].offset += num_bytes_written;
	  if (dir[dir_index].file_size < fds[fildes].offset) {
	    sb->total_data_storage += (fds[fildes].offset - dir[dir_index].file_size);
	    dir[dir_index].file_size = fds[fildes].offset;
	  }
	  return num_bytes_written;
        }
      }
      block_write(curr_block, temp_buf);
      ++block_offset;
    }

    
    while ((num_bytes_written < nbyte) && (block_offset < dir[dir_index].total_blocks)) {
        curr_block = get_next_block(curr_block);
        if (curr_block == -1) return -1;

        block_read(curr_block, temp_buf);
        for (unsigned short int i = 0; i < BLOCK_SIZE; ++i) {
            temp_buf[i] = buf_ptr[num_bytes_written++];
            if (num_bytes_written == nbyte) {
                block_write(curr_block, temp_buf);
                fds[fildes].offset += num_bytes_written;
                if (dir[dir_index].file_size < fds[fildes].offset) {
                    sb->total_data_storage += (fds[fildes].offset - dir[dir_index].file_size);
                    dir[dir_index].file_size = fds[fildes].offset;
                }
                return num_bytes_written;
            }
        }
        block_write(curr_block, temp_buf);
        ++block_offset;
    }
    
    while (num_bytes_written < nbyte) {
      curr_block = get_free_block(curr_block, dir_index);
	
        if (curr_block == -1) {
            fds[fildes].offset += num_bytes_written;
            if (dir[dir_index].file_size < fds[fildes].offset) {
                    sb->total_data_storage += (fds[fildes].offset - dir[dir_index].file_size);
                    dir[dir_index].file_size = fds[fildes].offset;
            }
            return num_bytes_written;
        }

        dir[dir_index].total_blocks++;
        sb->avail_data_blocks--;

        for (unsigned short int i = 0; i < BLOCK_SIZE; ++i) {
            temp_buf[i] = buf_ptr[num_bytes_written++];
            if (num_bytes_written == nbyte) {
                block_write(curr_block, temp_buf);
                fds[fildes].offset += num_bytes_written;
                if (dir[dir_index].file_size < fds[fildes].offset) {
                    sb->total_data_storage += (fds[fildes].offset - dir[dir_index].file_size);
                    dir[dir_index].file_size = fds[fildes].offset;
                }
                return num_bytes_written;
            }
        }
        block_write(curr_block, temp_buf);
    }
    return num_bytes_written;
}

int fs_get_filesize(int fildes) {
    if ((fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;
    
    int dir_index = fds[fildes].dir_index;
    return dir[dir_index].file_size;
}

int fs_lseek(int fildes, off_t offset) {
    if ((fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;
    
    //printf("FD: %d\n", fildes);

    int dir_index = fds[fildes].dir_index;
    if ((offset < 0) || (offset > dir[dir_index].file_size)) return -1;

    fds[fildes].offset = static_cast<unsigned int>(offset);
    
    return 0;
}

int fs_truncate(int fildes, off_t length) {
    if ((fildes < 0) || (fildes >= FD_LIM) || (fds[fildes].busy == false)) return -1;   

    int dir_index = fds[fildes].dir_index;



    if ((length < 0) || (dir[dir_index].file_size < static_cast<unsigned int>(length))) return -1;

    int curr_block = dir[dir_index].first_block_num;


    unsigned int counter = static_cast<unsigned int>(length);
    

    unsigned int old_file_size = dir[dir_index].file_size;


    while (counter > BLOCK_SIZE) {
        curr_block = get_next_block(curr_block);
        if (curr_block == -1) return -1;

        counter -= BLOCK_SIZE;
    }

    //     printf("FIRST BLOCK: %d\n", curr_block);
    //         printf("COUNTER: %d\n", counter);
    //             printf("OLD FILE SIZE: %d\n", old_file_size);




    // printf("FD1 OFFSET: %d\n", fds[0].offset);
    // printf("FD1 DIR INDEX: %d\n", fds[0].dir_index);
    // printf("FD1 DIR INDEX: %d\n", fds[fildes].dir_index);
    // printf("FD1 BUSY: %d\n", fds[fildes].busy);
    // printf("FD1 START BLOCK: %d\n", fds[fildes].file_start_block);
    // printf("NEXT BLOCK: %d\n", curr_block);


    curr_block = get_next_block(curr_block);


    while (curr_block != UNASSIGNED) {
        int next = fat[curr_block].next;
        
        //printf("NEXT VAL: %d\n", next);
        
        fat[curr_block].busy = false;
        fat[curr_block].next = UNASSIGNED;
        dir[dir_index].total_blocks--;
        sb->avail_data_blocks++;
        curr_block = next;
    }
    sb->total_data_storage = sb->total_data_storage - old_file_size + static_cast<unsigned int>(length);
    dir[dir_index].file_size = static_cast<unsigned int>(length);
    if (fds[fildes].offset > dir[dir_index].file_size) fds[fildes].offset = dir[dir_index].file_size; 

    return 0;
}

int get_free_block(int current_block, int dir_index) {
  //if (fat[current_block].next != UNASSIGNED) return -1;

    for (unsigned short int i = 4096; i < DISK_BLOCKS; ++i) {
      if (fat[i].busy == false) {
	fat[i].busy = true;
	if (current_block != UNASSIGNED) {
	  fat[current_block].next = i;
	  fat[i].next = UNASSIGNED;
	} else {
	  fat[i].next = UNASSIGNED;
	  dir[dir_index].first_block_num = i;	  
	}
	return i;
      }
    }    
    return -1;
}


int get_fd(unsigned short int dir_index) {
  for (unsigned short int i = 0; i < FD_LIM; ++i) {
        if (fds[i].busy == false) {
            fds[i].offset = 0;
            fds[i].dir_index = dir_index;
            fds[i].busy = true;
            return i;
        }
    }
    return -1;
}

int dir_file(char *name) {

//   printf("DIR SIZE: %d\n", sb->dir_size);
//    printf("FIRST BLOCK: %d\n", dir[0].first_block_num);
//     printf("TOTAL BLOCKS: %d\n", dir[0].total_blocks);
//     printf("TOTAL FDS: %d\n", dir[0].total_fds);
//     printf("FILE SIZE: %d\n", dir[0].file_size);
//     printf("FILE NAME: %s\n", dir[0].file_name);
  
  for (unsigned short int i = 0; i < sb->dir_size; ++i) {

    // printf("SHOULD GO HERE\n");
    // printf("IS BUSY: %d\n", dir[i].busy);
    // printf("COMPARE VALUE: %d\n", strcmp(name, dir[i].file_name));
    // printf("FILE NAME: %s\n", dir[i].file_name);
    if ((dir[i].busy == true) && (strcmp(name, dir[i].file_name) == 0)) return i;
  }


 // printf("SHOULDN'T GO HERE\n");
  return -1;
}

int get_next_block(unsigned short int current_block) {
    if (fat[current_block].next == UNASSIGNED) return -1;
    return fat[current_block].next;
}

