/*
 * Copyright 2014 Nate Woolls
 * Copyright 2014 GridSeed Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gc3355.h"

#include <unistd.h>
#include <string.h>

#include "miner.h"
#include "lowl-vcom.h"

#define GC3355_COMMAND_DELAY		20000
#define GC3355_INIT_DELAY			200000


#define GC3355_CHIP_NAME "gc3355"

static
const char *str_reset[] = {
	"55AAC000808080800000000001000000", // Chip reset
	NULL
};

static
const char *str_init[] = {
	"55AAC000C0C0C0C00500000001000000",
	"55AAEF020000000000000000000000000000000000000000",
	"55AAEF3020000000",
	NULL
};

static
const char *str_scrypt_reset[] = {
	"55AA1F2816000000",
	"55AA1F2817000000",
	NULL
};

/* commands to set core frequency */
static
const int opt_frequency[] = {
	250, 400, 450, 500, 550, 600, 650,
	700, 750, 800, 850, 900, 950, 1000,
	-1
};

static
const char *bin_frequency[] = {
	"\x55\xaa\xef\x00\x05\x00\x20\x01",
	"\x55\xaa\xef\x00\x05\x00\xe0\x01",
	"\x55\xaa\xef\x00\x05\x00\x20\x02",
	"\x55\xaa\xef\x00\x05\x00\x60\x82",
	"\x55\xaa\xef\x00\x05\x00\xa0\x82",
	"\x55\xaa\xef\x00\x05\x00\xe0\x82",
	"\x55\xaa\xef\x00\x05\x00\x20\x83",

	"\x55\xaa\xef\x00\x05\x00\x60\x83",
	"\x55\xaa\xef\x00\x05\x00\xa0\x83",
	"\x55\xaa\xef\x00\x05\x00\xe0\x83",
	"\x55\xaa\xef\x00\x05\x00\x20\x84",
	"\x55\xaa\xef\x00\x05\x00\x60\x84",
	"\x55\xaa\xef\x00\x05\x00\x80\x84",
	"\x55\xaa\xef\x00\x05\x00\xae\x84",
};

static
void gridseed_log_protocol(int fd, const char *buf, size_t size, const char *prefix)
{
	char hex[(size * 2) + 1];
	bin2hex(hex, buf, size);
	applog(LOG_DEBUG, "%s fd=%d: DEVPROTO: %s %s", GC3355_CHIP_NAME, fd, prefix, hex);
}

int gc3355_read(int fd, char *buf, int size)
{
	int read = serial_read(fd, buf, size);
	if (opt_dev_protocol)
		gridseed_log_protocol(fd, buf, size, "RECV");
	return read;
}

ssize_t gc3355_write(int fd, const void * const buf, const size_t size)
{
	if (opt_dev_protocol)
		gridseed_log_protocol(fd, buf, size, "SEND");
	return write(fd, buf, size);
}

static
void gc3355_send_cmds(int fd, const char *cmds[])
{
	int i = 0;
	unsigned char ob_bin[32];
	for(i = 0 ;; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		//allow NULL or "" to terminate
		if (cmds[i] == NULL)
			break;
		if (cmds[i][0] == 0)
			break;

		hex2bin(ob_bin, cmds[i], strlen(cmds[i]) / 2);
		gc3355_write(fd, ob_bin, 8);
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

static
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

void gc3355_init(struct cgpu_info *device)
{
	int fd = device->device_fd;

	gc3355_send_cmds(fd, str_reset);

	usleep(GC3355_INIT_DELAY);

	gc3355_send_cmds(fd, str_init);
	gc3355_send_cmds(fd, str_scrypt_reset);

	gc3355_set_core_freq(device);
}