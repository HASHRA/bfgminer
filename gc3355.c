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

// options configurable by the end-user

int opt_sha2_units = -1;
int opt_pll_freq = 0; // default is set in gc3355_set_pll_freq
bool opt_dual_mode = false;

#define GC3355_CHIP_NAME		"gc3355"

// thumb stick voltages mapped to sha2_units

#define DEFAULT_0_9V_SHA2		60
#define DEFAULT_1_2V_SHA2		0

static
const char *str_init[] =
{
	"55AAC000C0C0C0C00500000001000000", // set number of sub-chips (05 in this case)
	"55AAEF020000000000000000000000000000000000000000", // power down all SHA-2 modules
	"55AAEF3020000000", // Enable SHA-2 OR NOT - NO SCRYPT ACCEPTS WITHOUT THIS???
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
void gc3355_open_sha2_unit(int fd, int sha2_units)
{
	int unit_count = 0;
	unsigned char ob_bin[8];
	int i;

	unit_count = sha2_units;

	if (unit_count < 0)
		unit_count = 0;
	if (unit_count > 160)
		unit_count = 160;

	if (unit_count > 0 && unit_count <= 160)
	{
		for(i = 0; i <= unit_count; i++)
		{
			hex2bin(ob_bin, sha2_open_cmd[i], sizeof(ob_bin));
			gc3355_write(fd, ob_bin, 8);
			usleep(GC3355_COMMAND_DELAY);
		}
	}
	else if (unit_count == 0)
		gc3355_send_cmds(fd, sha2_gating_cmd);
}

void gc3355_sha2_init(int fd)
{
	gc3355_send_cmds(fd, sha2_gating_cmd);
	gc3355_send_cmds(fd, sha2_init_cmd);
}

void gc3355_init_usborb(int fd, int pll_freq, bool detect_only)
{
	gc3355_send_cmds(fd, str_gcp_reset_cmd);
	gc3355_send_cmds(fd, str_btc_reset_cmd);

	usleep(GC3355_COMMAND_DELAY);

	gc3355_send_cmds(fd, str_init);
	gc3355_send_cmds(fd, scrypt_reset_cmd);

	gc3355_set_pll_freq(fd, pll_freq);
}

void gc3355_init_usbstick(int fd, int pll_freq, bool detect_only)
{
	// reset chips
	gc3355_send_cmds(fd, str_gcp_reset_cmd);
	gc3355_send_cmds(fd, str_btc_reset_cmd);

	gc3355_set_dtr_status(fd, DTR_HIGH);
	usleep(GC3355_COMMAND_DELAY);
	gc3355_set_dtr_status(fd, DTR_LOW);

	if (opt_scrypt && !opt_dual_mode)
	{
		gc3355_scrypt_only_init(fd);
	}
	else
	{
		gc3355_sha2_init(fd);
		gc3355_scrypt_init(fd);
	}
	
	gc3355_set_pll_freq(fd, pll_freq);

	usleep(GC3355_COMMAND_DELAY);

	if (!detect_only) {

		if (!opt_scrypt)
		{
			// open sha2 units
			if (opt_sha2_units == -1)
			{
				if (gc3355_get_cts_status(fd) == 1)
					opt_sha2_units = DEFAULT_1_2V_SHA2; //dip-switch in L position
				else
					opt_sha2_units = DEFAULT_0_9V_SHA2; // dip-switch in B position
			}

			gc3355_open_sha2_unit(fd, opt_sha2_units);
		}
		gc3355_set_rts_status(fd, RTS_HIGH);

	}

}

void gc3355_scrypt_init(int fd)
{
	gc3355_send_cmds(fd, scrypt_init_cmd);
}

void gc3355_scrypt_only_init(int fd)
{
	gc3355_send_cmds(fd, sha2_gating_cmd);
	gc3355_send_cmds(fd, scrypt_only_init_cmd);
	gc3355_send_cmds(fd, scrypt_restart_cmd);
}

void gc3355_scrypt_restart(int fd)
{
	gc3355_send_cmds(fd, scrypt_restart_cmd);
}

void gc3355_scrypt_reset(int fd)
{
	gc3355_send_cmds(fd, scrypt_reset_cmd);
}

void gc3355_scrypt_prepare_work(unsigned char cmd[156], struct work *work)
{
	cmd[0] = 0x55;
	cmd[1] = 0xaa;
	cmd[2] = 0x1f;
	cmd[3] = 0x00;

	memcpy(cmd+4, work->target, 32);
	memcpy(cmd+36, work->midstate, 32);
	memcpy(cmd+68, work->data, 80);

	// nonce_max
	cmd[148] = 0xff;
	cmd[149] = 0xff;
	cmd[150] = 0xff;
	cmd[151] = 0xff;

	// taskid
	cmd[152] = 0x12;
	cmd[153] = 0x34;
	cmd[154] = 0x56;
	cmd[155] = 0x78;
}

void gc3355_sha2_prepare_work(unsigned char cmd[52], struct work *work)
{
	cmd[0] = 0x55;
	cmd[1] = 0xaa;
	cmd[2] = 0x0f;
	cmd[3] = 0x00;

	uint8_t temp_bin[64];
	memset(temp_bin, 0, 64);

	memcpy(temp_bin, work->midstate, 32);
	memcpy(temp_bin + 52, work->data + 64, 12);

	memcpy(cmd + 8, work->midstate, 32);
	memcpy(cmd + 40, temp_bin + 52, 12);
}

uint32_t gc3355_get_firmware_version(int fd)
{
	unsigned char detect_data[16];
	int size = sizeof(detect_data);

	gc3355_send_cmds(fd, firmware_request_cmd);

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
