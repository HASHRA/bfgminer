/*
* Copyright 2014 Nate Woolls
* Copyright 2014 GridSeed Team
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the Free
* Software Foundation; either version 3 of the License, or (at your option)
* any later version. See COPYING for more details.
*/

#include "gc3355.h"

#include <unistd.h>
#include <string.h>

#include "miner.h"
#include "lowl-vcom.h"

#define GC3355_COMMAND_DELAY 20000
#define GC3355_INIT_DELAY 200000


#define GC3355_CHIP_NAME "gc3355"

static
const char *str_reset[] =
{
"55AAC000808080800000000001000000", // Chip reset
NULL
};

static
const char *str_init[] =
{
"55AAC000C0C0C0C00500000001000000",
"55AAEF020000000000000000000000000000000000000000",
"55AAEF3020000000",
NULL
};

static
const char *str_scrypt_reset[] =
{
"55AA1F2816000000",
"55AA1F2817000000",
NULL
};

/* commands to set core frequency */
static
const int opt_frequency[] =
{
	    250, 400, 450, 500, 550, 600, 650,
      700, 706, 713, 719, 725, 731, 738, 744,
      750, 756, 763, 769, 775, 781, 788, 794,
      800, 813, 825, 838, 850, 863, 875, 888,
      900, 913, 925, 938, 950, 963, 975, 988,
     1000, 1013, 1025, 1038, 1050, 1063, 1075, 1088,
     1100, 1113, 1125, 1138, 1150, 1163, 1175, 1188,
     1200, 1213, 1225, 1238, 1250, 1263, 1275, 1288,
     1300, 1313, 1325, 1338, 1350, 1363, 1375, 1388,
     1400,
       -1
-1
};

static
const char *bin_frequency[] =
{
"\x55\xaa\xef\x00\x05\x00\x20\x01",
"\x55\xaa\xef\x00\x05\x00\xe0\x01",
"\x55\xaa\xef\x00\x05\x00\x20\x02",
"\x55\xaa\xef\x00\x05\x00\x60\x82",
"\x55\xaa\xef\x00\x05\x00\xa0\x82",
"\x55\xaa\xef\x00\x05\x00\xe0\x82",
"\x55\xaa\xef\x00\x05\x00\x20\x83",

 "\x55\xaa\xef\x00\x05\x00\x60\x83",
"\x55\xaa\xef\x00\x05\x00\x03\x8e",
"\x55\xaa\xef\x00\x05\x00\x01\x87",
"\x55\xaa\xef\x00\x05\x00\x43\x8e",
"\x55\xaa\xef\x00\x05\x00\x80\x83",
"\x55\xaa\xef\x00\x05\x00\x83\x8e",
"\x55\xaa\xef\x00\x05\x00\x41\x87",
"\x55\xaa\xef\x00\x05\x00\xc3\x8e",

"\x55\xaa\xef\x00\x05\x00\xa0\x83",
"\x55\xaa\xef\x00\x05\x00\x03\x8f",
"\x55\xaa\xef\x00\x05\x00\x81\x87",
"\x55\xaa\xef\x00\x05\x00\x43\x8f",
"\x55\xaa\xef\x00\x05\x00\xc0\x83",
"\x55\xaa\xef\x00\x05\x00\x83\x8f",
"\x55\xaa\xef\x00\x05\x00\xc1\x87",
"\x55\xaa\xef\x00\x05\x00\xc3\x8f",

"\x55\xaa\xef\x00\x05\x00\xe0\x83",
"\x55\xaa\xef\x00\x05\x00\x01\x88",
"\x55\xaa\xef\x00\x05\x00\x00\x84",
"\x55\xaa\xef\x00\x05\x00\x41\x88",
"\x55\xaa\xef\x00\x05\x00\x20\x84",
"\x55\xaa\xef\x00\x05\x00\x81\x88",
"\x55\xaa\xef\x00\x05\x00\x40\x84",
"\x55\xaa\xef\x00\x05\x00\xc1\x88",

"\x55\xaa\xef\x00\x05\x00\x60\x84",
"\x55\xaa\xef\x00\x05\x00\x01\x89",
"\x55\xaa\xef\x00\x05\x00\x80\x84",
"\x55\xaa\xef\x00\x05\x00\x41\x89",
"\x55\xaa\xef\x00\x05\x00\xa0\x84",
"\x55\xaa\xef\x00\x05\x00\x81\x89",
"\x55\xaa\xef\x00\x05\x00\xc0\x84",
"\x55\xaa\xef\x00\x05\x00\xc1\x89",

"\x55\xaa\xef\x00\x05\x00\xe0\x84",
"\x55\xaa\xef\x00\x05\x00\x01\x8a",
"\x55\xaa\xef\x00\x05\x00\x00\x85",
"\x55\xaa\xef\x00\x05\x00\x41\x8a",
"\x55\xaa\xef\x00\x05\x00\x20\x85",
"\x55\xaa\xef\x00\x05\x00\x81\x8a",
"\x55\xaa\xef\x00\x05\x00\x40\x85",
"\x55\xaa\xef\x00\x05\x00\xc1\x8a",

"\x55\xaa\xef\x00\x05\x00\x60\x85",
"\x55\xaa\xef\x00\x05\x00\x01\x8b",
"\x55\xaa\xef\x00\x05\x00\x80\x85",
"\x55\xaa\xef\x00\x05\x00\x41\x8b",
"\x55\xaa\xef\x00\x05\x00\xa0\x85",
"\x55\xaa\xef\x00\x05\x00\x81\x8b",
"\x55\xaa\xef\x00\x05\x00\xc0\x85",
"\x55\xaa\xef\x00\x05\x00\xc1\x8b",

"\x55\xaa\xef\x00\x05\x00\xe0\x85",
"\x55\xaa\xef\x00\x05\x00\x01\x8c",
"\x55\xaa\xef\x00\x05\x00\x00\x86",
"\x55\xaa\xef\x00\x05\x00\x41\x8c",
"\x55\xaa\xef\x00\x05\x00\x20\x86",
"\x55\xaa\xef\x00\x05\x00\x81\x8c",
"\x55\xaa\xef\x00\x05\x00\x40\x86",
"\x55\xaa\xef\x00\x05\x00\xc1\x8c",

"\x55\xaa\xef\x00\x05\x00\x60\x86",
"\x55\xaa\xef\x00\x05\x00\x01\x8d",
"\x55\xaa\xef\x00\x05\x00\x80\x86",
"\x55\xaa\xef\x00\x05\x00\x41\x8d",
"\x55\xaa\xef\x00\x05\x00\xa0\x86",
"\x55\xaa\xef\x00\x05\x00\x81\x8d",
"\x55\xaa\xef\x00\x05\x00\xc0\x86",
"\x55\xaa\xef\x00\x05\x00\xc1\x8d",

"\x55\xaa\xef\x00\x05\x00\xe0\x86",
};

static
void gc3355_log_protocol(int fd, const char *buf, size_t size, const char *prefix)
{
char hex[(size * 2) + 1];
bin2hex(hex, buf, size);
applog(LOG_DEBUG, "%s fd=%d: DEVPROTO: %s(%3d) %s", GC3355_CHIP_NAME, fd, prefix, size, hex);
}

int gc3355_read(int fd, char *buf, size_t size)
{
size_t read;
int tries = 20;

while (tries > 0)
{
read = serial_read(fd, buf, size);
if (read > 0)
break;

tries--;
}

if(unlikely(tries == 0))
return -1;

if ((read > 0) && opt_dev_protocol)
gc3355_log_protocol(fd, buf, size, "RECV");

return read;
}

ssize_t gc3355_write(int fd, const void * const buf, const size_t size)
{
if (opt_dev_protocol)
gc3355_log_protocol(fd, buf, size, "SEND");

return write(fd, buf, size);
}

int gc3355_open(const char *path)
{
return serial_open(path, 115200, 1, true);
}

int gc3355_close(int fd)
{
return serial_close(fd);
}

static
void gc3355_send_cmds(int fd, const char *cmds[])
{
int i = 0;
unsigned char ob_bin[512];
for(i = 0 ;; i++)
{
memset(ob_bin, 0, sizeof(ob_bin));

const char *cmd = cmds[i];

if (cmd == NULL)
break;

int size = strlen(cmd) / 2;
hex2bin(ob_bin, cmd, size);
gc3355_write(fd, ob_bin, size);

usleep(GC3355_COMMAND_DELAY);
}
}

static
int gc3355_find_freq_index(int freq)
{
for (int i = 0; opt_frequency[i] != -1; i++)
if (freq == opt_frequency[i])
return i;

return gc3355_find_freq_index(GC3355_DEFAULT_FREQUENCY);
}

void gc3355_set_core_freq(struct cgpu_info *device)
{
struct gc3355_info *info = (struct gc3355_info *)(device->device_data);
int fd = device->device_fd;
int idx = gc3355_find_freq_index(info->freq);

unsigned char freq_cmd[8];
memcpy(freq_cmd, bin_frequency[idx], 8);
gc3355_write(fd, freq_cmd, sizeof(freq_cmd));

usleep(GC3355_COMMAND_DELAY);

applog(LOG_DEBUG, "%s fd=%d: Set %s core frequency to %d MHz", GC3355_CHIP_NAME, fd, GC3355_CHIP_NAME, info->freq);
}

void gc3355_scrypt_reset(struct cgpu_info *device)
{
int fd = device->device_fd;
gc3355_send_cmds(fd, str_scrypt_reset);
}

void gc3355_init(struct cgpu_info *device)
{
int fd = device->device_fd;

gc3355_send_cmds(fd, str_reset);

usleep(GC3355_INIT_DELAY);

gc3355_send_cmds(fd, str_init);
gc3355_send_cmds(fd, str_scrypt_reset);

gc3355_set_core_freq(device);
}
