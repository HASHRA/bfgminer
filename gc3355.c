/*
 * Copyright 2014 Nate Woolls
 * Copyright 2014 GridSeed Team
 * Copyright 2014 Dualminer Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gc3355.h"
#include "gc3355-commands.h"

#include <string.h>
#include "miner.h"
#include "driver-icarus.h"
#include "logging.h"
#include "lowl-vcom.h"

#ifndef WIN32
  #include <sys/ioctl.h>
#else
  #include <io.h>
#endif

// GridSeed common code begins here

#define GC3355_COMMAND_DELAY		20000

#define GC3355_CHIP_NAME			"gc3355"

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

		if (cmds[i][0] == 0)
			break;

		int size = strlen(cmd) / 2;
		hex2bin(ob_bin, cmd, size);
		gc3355_write(fd, ob_bin, size);

		usleep(GC3355_COMMAND_DELAY);
	}
}

void gc3355_set_pll_freq(const int fd, const int pll_freq)
{
	int actual_freq = pll_freq;

	switch(pll_freq)
	{
		case 400:
		{
			gc3355_send_cmds(fd, pll_freq_400M_cmd);
			break;
		}
		case 500:
		{
			gc3355_send_cmds(fd, pll_freq_500M_cmd);
			break;
		}
		case 550:
		{
			gc3355_send_cmds(fd, pll_freq_550M_cmd);
			break;
		}
		case 600:
		{
			gc3355_send_cmds(fd, pll_freq_600M_cmd);
			break;
		}
		case 650:
		{
			gc3355_send_cmds(fd, pll_freq_650M_cmd);
			break;
		}
		case 700:
		{
			gc3355_send_cmds(fd, pll_freq_700M_cmd);
			break;
		}
		case 750:
		{
			gc3355_send_cmds(fd, pll_freq_750M_cmd);
			break;
		}
		case 800:
		{
			gc3355_send_cmds(fd, pll_freq_800M_cmd);
			break;
		}
		case 850:
		{
			gc3355_send_cmds(fd, pll_freq_850M_cmd);
			break;
		}
		case 900:
		{
			gc3355_send_cmds(fd, pll_freq_900M_cmd);
			break;
		}
		case 950:
		{
			gc3355_send_cmds(fd, pll_freq_950M_cmd);
			break;
		}
		case 1000:
		{
			gc3355_send_cmds(fd, pll_freq_1000M_cmd);
			break;
		}
		case 1100:
		{
			gc3355_send_cmds(fd, pll_freq_1100M_cmd);
			break;
		}
		case 1200:
		{
			gc3355_send_cmds(fd, pll_freq_1200M_cmd);
			break;
		}
		default:
		{
			if (gc3355_get_cts_status(fd) == 1)
				//1.2v - Scrypt mode
				actual_freq = GC3355_STICK_SM_DEFAULT_FREQUENCY;

			else
				//0.9v - Scrypt + SHA mode
				actual_freq = GC3355_STICK_DM_DEFAULT_FREQUENCY;

			gc3355_set_pll_freq(fd, actual_freq);
		}
	}

	if (pll_freq == actual_freq)
		applog(LOG_DEBUG, "%s fd=%d: Set %s core frequency to %d MHz", GC3355_CHIP_NAME, fd, GC3355_CHIP_NAME, actual_freq);
}

// 5-chip GridSeed support begins here

#define GC3355_INIT_DELAY			200000

static
const char *str_init[] =
{
	"55AAC000C0C0C0C00500000001000000", // set number of sub-chips (05 in this case)
	"55AAEF020000000000000000000000000000000000000000", // power down all SHA-2 modules
	"55AAEF3020000000", // Enable SHA-2 OR NOT - NO SCRYPT ACCEPTS WITHOUT THIS???
	NULL
};

static
const char *str_scrypt_reset[] =
{
	"55AA1F2816000000", // Reset Scrypt(?)
	"55AA1F2817000000", // Enable GCP(?)
	NULL
};

static
void gc3355_log_protocol(int fd, const char *buf, size_t size, const char *prefix)
{
	char hex[(size * 2) + 1];
	bin2hex(hex, buf, size);
	applog(LOG_DEBUG, "%s fd=%d: DEVPROTO: %s(%3lu) %s", GC3355_CHIP_NAME, fd, prefix, size, hex);
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

void gc3355_scrypt_reset(struct cgpu_info *device)
{
	int fd = device->device_fd;
	gc3355_send_cmds(fd, str_scrypt_reset);
}

void gc3355_init_usborb(struct cgpu_info *device)
{
	int fd = device->device_fd;

	gc3355_send_cmds(fd, str_gcp_reset);
	gc3355_send_cmds(fd, str_btc_reset);

	usleep(GC3355_INIT_DELAY);

	gc3355_send_cmds(fd, str_init);
	gc3355_send_cmds(fd, str_scrypt_reset);

	struct gc3355_info *info = (struct gc3355_info *)(device->device_data);
	gc3355_set_pll_freq(fd, info->freq);
}

uint32_t gc3355_get_firmware_version(int fd)
{
	unsigned char detect_data[16];
	int size = sizeof(detect_data);

	gc3355_send_cmds(fd, firmware_request);

	char buf[GC3355_READ_SIZE];
	int read = gc3355_read(fd, buf, GC3355_READ_SIZE);
	if (read != GC3355_READ_SIZE)
	{
		applog(LOG_ERR, "%s: Failed reading work from %d", GC3355_CHIP_NAME, fd);
		return -1;
	}

	// firmware response begins with 55aac000 90909090
	if (memcmp(buf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GC3355_READ_SIZE - 4) != 0)
	{
		return -1;
	}

	uint32_t fw_version = le32toh(*(uint32_t *)(buf + 8));

	return fw_version;
}

// 1-chip DualMiner support begins here

#define DEFAULT_DELAY_TIME 2000

#define DEFAULT_0_9V_sha2 "60"
#define DEFAULT_1_2V_sha2 "0"

char *opt_dualminer_sha2_gating = NULL;
int opt_pll_freq = 0; // default is set in gc3355_set_pll_freq
int opt_sha2_number = 160;
bool opt_dual_mode = false;

void gc3355_scrypt_restart(int fd)
{
	gc3355_send_cmds(fd, scrypt_restart);
}

void gc3355_open_sha2_unit(int fd, char *opt_sha2_gating)
{
	int unit_count = 0;
	unsigned char ob_bin[8];
	int i;

	unit_count = atoi(opt_sha2_gating);

	if (unit_count < 0)
		unit_count = 0;
	if (unit_count > 160)
		unit_count = 160;

	if (unit_count > 0 && unit_count <= 160)
	{
		for(i = 0; i <= unit_count; i++)
		{
			hex2bin(ob_bin, sha2_single_open[i], sizeof(ob_bin));
			icarus_write(fd, ob_bin, 8);
			usleep(DEFAULT_DELAY_TIME * 2);
		}
		opt_sha2_number = unit_count;
	}
	else if (unit_count == 0)
		gc3355_send_cmds(fd, sha2_gating_tmpl);
}

void gc3355_scrypt_only_init(int fd)
{
	gc3355_send_cmds(fd, sha2_gating_tmpl);
	gc3355_send_cmds(fd, scrypt_only_init);
	gc3355_send_cmds(fd, scrypt_restart);

	gc3355_set_pll_freq(fd, opt_pll_freq);
}

// initialize for Dual Mode
void gc3355_dualmode_init(int fd)
{
	if (opt_scrypt)
		gc3355_send_cmds(fd, scrypt_init);
	else
	{
		gc3355_send_cmds(fd, sha2_gating_tmpl);
		gc3355_send_cmds(fd, sha2_init);
	}

	if (!opt_scrypt)
		gc3355_set_pll_freq(fd, opt_pll_freq);
}

void gc3355_init_usbstick(int fd, char *sha2_unit, bool is_scrypt_only)
{
	gc3355_send_cmds(fd, str_gcp_reset);
	gc3355_send_cmds(fd, str_btc_reset);

	if (sha2_unit != NULL)
		gc3355_open_sha2_unit(fd, sha2_unit);
	else
	{
		if (gc3355_get_cts_status(fd) == 1)
		{
			//1.2v - Scrypt mode
			if (opt_scrypt)
			{
				if (is_scrypt_only)
					gc3355_scrypt_only_init(fd);
			}
			else
				gc3355_open_sha2_unit(fd, DEFAULT_1_2V_sha2);
		}
		else
		{
			//0.9v - Scrypt + SHA mode
			if (opt_scrypt)
			{
				if (is_scrypt_only)
					gc3355_scrypt_only_init(fd);
			}
			else
				gc3355_open_sha2_unit(fd, DEFAULT_0_9V_sha2);
		}
	}
}
