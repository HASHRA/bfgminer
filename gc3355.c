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

// GridSeed support begins here

#define GC3355_COMMAND_DELAY		20000
#define GC3355_INIT_DELAY			200000


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
	700, 750, 800, 850, 900, 950, 1000,
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
	"\x55\xaa\xef\x00\x05\x00\xa0\x83",
	"\x55\xaa\xef\x00\x05\x00\xe0\x83",
	"\x55\xaa\xef\x00\x05\x00\x20\x84",
	"\x55\xaa\xef\x00\x05\x00\x60\x84",
	"\x55\xaa\xef\x00\x05\x00\x80\x84",
	"\x55\xaa\xef\x00\x05\x00\xae\x84",
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

// DualMiner support begins here

#define DEFAULT_DELAY_TIME 2000

#define HUBFANS_0_9V_sha2 "60"
#define HUBFANS_1_2V_sha2 "0"
#define DEFAULT_0_9V_sha2 "60"
#define DEFAULT_1_2V_sha2 "0"

static
const char *pll_freq_1200M_cmd[] =
{
	"55AAEF000500E085",
	"55AA0FFFB02800C0",
	"",
};

static
const char *pll_freq_1100M_cmd[] =
{
	"55AAEF0005006085",
	"55AA0FFF4C2500C0",
	"",
};

static
const char *pll_freq_1000M_cmd[] =
{
	"55AAEF000500E084",
	"55AA0FFFE82100C0",
	"",
};

static
const char *pll_freq_950M_cmd[] =
{
	"55AAEF000500A084",
	"55AA0FFF362000C0",
	"",
};

static
const char *pll_freq_900M_cmd[] =
{
	"55AAEF0005006084",
	"55AA0FFF841E00C0",
	"",
};

static
const char *pll_freq_850M_cmd[] =
{
	"55AAEF0005002084",
	"55AA0FFFD21C00C0",
	"",
};

static
const char *pll_freq_800M_cmd[] =
{
	"55AAEF000500E083",
	"55AA0FFF201B00C0",
	"",
};

static
const char *pll_freq_750M_cmd[] =
{
	"55AAEF000500A083",
	"55AA0FFF6E1900C0",
	"",
};

static
const char *pll_freq_700M_cmd[] =
{
	"55AAEF0005006083",
	"55AA0FFFBC1700C0",
	"",
};

static
const char *pll_freq_650M_cmd[] =
{
	"55AAEF0005002083",
	"55AA0FFF0A1600C0",
	"",
};

static
const char *pll_freq_600M_cmd[] =
{
	"55AAEF000500E082",
	"55AA0FFF581400C0",
	"",
};

static
const char *pll_freq_550M_cmd[] =
{
	"55AAEF000500A082",
	"55AA0FFFA61200C0",
	"",
};

static
const char *pll_freq_500M_cmd[] =
{
	"55AAEF0005006082",
	"55AA0FFFF41000C0",
	"",
};

static
const char *pll_freq_400M_cmd[] =
{
	"55AAEF000500E081",
	"55AA0FFF900D00C0",
	"",
};

static
const char *sha2_gating[] =
{
	"55AAEF0200000000",
	"55AAEF0300000000",
	"55AAEF0400000000",
	"55AAEF0500000000",
	"55AAEF0600000000",
	"",
};

static
const char *sha2_single_open[] =
{
	"55AAEF0200000001",
	"55AAEF0200000003",
	"55AAEF0200000007",
	"55AAEF020000000F",
	"55AAEF020000001F",
	"55AAEF020000003F",
	"55AAEF020000007F",
	"55AAEF02000000FF",
	"55AAEF02000001FF",
	"55AAEF02000003FF",
	"55AAEF02000007FF",
	"55AAEF0200000FFF",
	"55AAEF0200001FFF",
	"55AAEF0200003FFF",
	"55AAEF0200007FFF",
	"55AAEF020000FFFF",
	"55AAEF020001FFFF",
	"55AAEF020003FFFF",
	"55AAEF020007FFFF",
	"55AAEF02000FFFFF",
	"55AAEF02001FFFFF",
	"55AAEF02003FFFFF",
	"55AAEF02007FFFFF",
	"55AAEF0200FFFFFF",
	"55AAEF0201FFFFFF",
	"55AAEF0203FFFFFF",
	"55AAEF0207FFFFFF",
	"55AAEF020FFFFFFF",
	"55AAEF021FFFFFFF",
	"55AAEF023FFFFFFF",
	"55AAEF027FFFFFFF",
	"55AAEF02FFFFFFFF",
	"55AAEF0300000001",
	"55AAEF0300000003",
	"55AAEF0300000007",
	"55AAEF030000000F",
	"55AAEF030000001F",
	"55AAEF030000003F",
	"55AAEF030000007F",
	"55AAEF03000000FF",
	"55AAEF03000001FF",
	"55AAEF03000003FF",
	"55AAEF03000007FF",
	"55AAEF0300000FFF",
	"55AAEF0300001FFF",
	"55AAEF0300003FFF",
	"55AAEF0300007FFF",
	"55AAEF030000FFFF",
	"55AAEF030001FFFF",
	"55AAEF030003FFFF",
	"55AAEF030007FFFF",
	"55AAEF03000FFFFF",
	"55AAEF03001FFFFF",
	"55AAEF03003FFFFF",
	"55AAEF03007FFFFF",
	"55AAEF0300FFFFFF",
	"55AAEF0301FFFFFF",
	"55AAEF0303FFFFFF",
	"55AAEF0307FFFFFF",
	"55AAEF030FFFFFFF",
	"55AAEF031FFFFFFF",
	"55AAEF033FFFFFFF",
	"55AAEF037FFFFFFF",
	"55AAEF03FFFFFFFF",
	"55AAEF0400000001",
	"55AAEF0400000003",
	"55AAEF0400000007",
	"55AAEF040000000F",
	"55AAEF040000001F",
	"55AAEF040000003F",
	"55AAEF040000007F",
	"55AAEF04000000FF",
	"55AAEF04000001FF",
	"55AAEF04000003FF",
	"55AAEF04000007FF",
	"55AAEF0400000FFF",
	"55AAEF0400001FFF",
	"55AAEF0400003FFF",
	"55AAEF0400007FFF",
	"55AAEF040000FFFF",
	"55AAEF040001FFFF",
	"55AAEF040003FFFF",
	"55AAEF040007FFFF",
	"55AAEF04000FFFFF",
	"55AAEF04001FFFFF",
	"55AAEF04003FFFFF",
	"55AAEF04007FFFFF",
	"55AAEF0400FFFFFF",
	"55AAEF0401FFFFFF",
	"55AAEF0403FFFFFF",
	"55AAEF0407FFFFFF",
	"55AAEF040FFFFFFF",
	"55AAEF041FFFFFFF",
	"55AAEF043FFFFFFF",
	"55AAEF047FFFFFFF",
	"55AAEF04FFFFFFFF",
	"55AAEF0500000001",
	"55AAEF0500000003",
	"55AAEF0500000007",
	"55AAEF050000000F",
	"55AAEF050000001F",
	"55AAEF050000003F",
	"55AAEF050000007F",
	"55AAEF05000000FF",
	"55AAEF05000001FF",
	"55AAEF05000003FF",
	"55AAEF05000007FF",
	"55AAEF0500000FFF",
	"55AAEF0500001FFF",
	"55AAEF0500003FFF",
	"55AAEF0500007FFF",
	"55AAEF050000FFFF",
	"55AAEF050001FFFF",
	"55AAEF050003FFFF",
	"55AAEF050007FFFF",
	"55AAEF05000FFFFF",
	"55AAEF05001FFFFF",
	"55AAEF05003FFFFF",
	"55AAEF05007FFFFF",
	"55AAEF0500FFFFFF",
	"55AAEF0501FFFFFF",
	"55AAEF0503FFFFFF",
	"55AAEF0507FFFFFF",
	"55AAEF050FFFFFFF",
	"55AAEF051FFFFFFF",
	"55AAEF053FFFFFFF",
	"55AAEF057FFFFFFF",
	"55AAEF05FFFFFFFF",
	"55AAEF0600000001",
	"55AAEF0600000003",
	"55AAEF0600000007",
	"55AAEF060000000F",
	"55AAEF060000001F",
	"55AAEF060000003F",
	"55AAEF060000007F",
	"55AAEF06000000FF",
	"55AAEF06000001FF",
	"55AAEF06000003FF",
	"55AAEF06000007FF",
	"55AAEF0600000FFF",
	"55AAEF0600001FFF",
	"55AAEF0600003FFF",
	"55AAEF0600007FFF",
	"55AAEF060000FFFF",
	"55AAEF060001FFFF",
	"55AAEF060003FFFF",
	"55AAEF060007FFFF",
	"55AAEF06000FFFFF",
	"55AAEF06001FFFFF",
	"55AAEF06003FFFFF",
	"55AAEF06007FFFFF",
	"55AAEF0600FFFFFF",
	"55AAEF0601FFFFFF",
	"55AAEF0603FFFFFF",
	"55AAEF0607FFFFFF",
	"55AAEF060FFFFFFF",
	"55AAEF061FFFFFFF",
	"55AAEF063FFFFFFF",
	"55AAEF067FFFFFFF",
	"55AAEF06FFFFFFFF",
	"",
};

static
const char *scrypt_only_init[] =
{
	"55AAEF0200000000",
	"55AAEF0300000000",
	"55AAEF0400000000",
	"55AAEF0500000000",
	"55AAEF0600000000",
	"55AAEF3040000000",
	"55AA1F2810000000",
	"55AA1F2813000000",
	"",
};

char *opt_dualminer_sha2_gating = NULL;
int opt_pll_freq = 0; // default is set in gc3355_pll_freq_init2
int opt_sha2_number = 160;
bool opt_hubfans = false;
bool opt_dual_mode = false;

void gc3355_dual_reset(int fd)
{
	static int i = 0;

#ifdef WIN32
	DCB dcb;

	memset(&dcb, 0, sizeof(DCB));
	GetCommState(_get_osfhandle(fd), &dcb);
	dcb.fDtrControl = DTR_CONTROL_ENABLE;
	SetCommState(_get_osfhandle(fd), &dcb);
	Sleep(1);
	GetCommState(_get_osfhandle(fd), &dcb);
	dcb.fDtrControl = DTR_CONTROL_DISABLE;
	SetCommState(_get_osfhandle(fd), &dcb);

#else

	int dtr_flag = 0;
	ioctl(fd, TIOCMGET, &dtr_flag);
	dtr_flag |= TIOCM_DTR;
	ioctl(fd, TIOCMSET, &dtr_flag);
	usleep(1000);
	ioctl(fd, TIOCMGET, &dtr_flag);
	dtr_flag &= ~TIOCM_DTR;
	ioctl(fd, TIOCMSET, &dtr_flag);

#endif
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

		if (cmds[i][0] == 0)
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

void gc3355_init_usborb(struct cgpu_info *device)
{
	int fd = device->device_fd;

	gc3355_send_cmds(fd, str_reset);

	usleep(GC3355_INIT_DELAY);

	gc3355_send_cmds(fd, str_init);
	gc3355_send_cmds(fd, str_scrypt_reset);

	gc3355_set_core_freq(device);
}

void gc3355_opt_scrypt_init(int fd)
{
	const char *initscrypt_ob[] =
	{
		"55AA1F2810000000",
		"55AA1F2813000000",
		""
	};

	gc3355_send_cmds(fd, initscrypt_ob);
}

static
void gc3355_pll_freq_init(int fd, char *pll_freq)
{
	const char *pll_freq_cmd[] =
	{
		"400",
		"55AAEF000500E081",
		"55AA0FFF900D00C0",
		"1200",
		"55AAEF000500E085",
		"55AA0FFFB02800C0",
		"1100",
		"55AAEF0005006085",
		"55AA0FFF4C2500C0",
		"1000",
		"55AAEF000500E084",
		"55AA0FFFE82100C0",
		"950",
		"55AAEF000500A084",
		"55AA0FFF362000C0",
		"900",
		"55AAEF0005006084",
		"55AA0FFF841E00C0",
		"850",
		"55AAEF0005002084",
		"55AA0FFFD21C00C0",
		"800",
		"55AAEF000500E083",
		"55AA0FFF201B00C0",
		"750",
		"55AAEF000500A083",
		"55AA0FFF6E1900C0",
		"700",
		"55AAEF0005006083",
		"55AA0FFFBC1700C0",
		"650",
		"55AAEF0005002083",
		"55AA0FFF0A1600C0",
		"600",
		"55AAEF000500E082",
		"55AA0FFF581400C0",
		"550",
		"55AAEF000500A082",
		"55AA0FFFA61200C0",
		"500",
		"55AAEF0005006082",
		"55AA0FFFF41000C0",
	};
	unsigned char pllob_bin[10];
	int i;
	int found_pll = -1;

	if (pll_freq == NULL)
		found_pll = 0;
	else
	{
		for(i = 0; i < 48; i++)
		{
			if (pll_freq_cmd[i][0] == '\0')
				break;

			applog(LOG_DEBUG, "GC3355: pll_freq_cmd[i] is %s, freq %s \n",pll_freq_cmd[i],pll_freq);
			if (!strcmp(pll_freq, pll_freq_cmd[i]))
			{
				found_pll = i;
				opt_pll_freq = atoi(pll_freq);
			}
		}

		if (found_pll == -1)
			found_pll = 0;
	}

	if (found_pll != -1)
	{
		applog(LOG_DEBUG, "GC3355: found freq %s in the support list\n", pll_freq);
		memset(pllob_bin, 0, sizeof(pllob_bin));
		applog(LOG_DEBUG, "GC3355: set freq %s, reg1=%s in the support list\n", pll_freq, pll_freq_cmd[found_pll + 1]);
		hex2bin(pllob_bin, pll_freq_cmd[found_pll + 1], sizeof(pllob_bin));
		icarus_write(fd, pllob_bin, 8);
		usleep(1000);
		memset(pllob_bin, 0, sizeof(pllob_bin));
		applog(LOG_DEBUG, "GC3355: set freq %s, reg2=%s in the support list\n", pll_freq, pll_freq_cmd[found_pll + 2]);
		hex2bin(pllob_bin, pll_freq_cmd[found_pll + 2], sizeof(pllob_bin));
		icarus_write(fd, pllob_bin, 8);
		usleep(1000);
	}
	else
		applog(LOG_ERR, "GC3355: freq %s is not supported\n", pll_freq);
}

int gc3355_get_cts_status(int fd)
{
	int ret;
	int status = 0;
#ifdef WIN32
	GetCommModemStatus(_get_osfhandle(fd), &status);
	applog(LOG_DEBUG, "Get CTS Status is : %d [Windows: 0 is 1.2; 16 is 0.9]\n", status);
	ret = (status == 0) ? 1 : 0;
	return ret;
#else
	ioctl(fd, TIOCMGET, &status);
	ret = (status & 0x20) ? 0 : 1;
	applog(LOG_DEBUG, "Get CTS Status is : %d [Linux: 1 is 1.2; 0 is 0.9]\n", ret);
	return ret;
#endif
}

void gc3355_set_rts_status(int fd, unsigned int value)
{
#ifdef WIN32
	DCB dcb;
	memset(&dcb, 0, sizeof(DCB));
	GetCommState(_get_osfhandle(fd), &dcb);
	if (value != 0)
		dcb.fRtsControl = RTS_CONTROL_ENABLE;
	else
		dcb.fRtsControl = RTS_CONTROL_DISABLE;
	SetCommState(_get_osfhandle(fd), &dcb);
#else
	int rts_flag = 0;
	ioctl(fd, TIOCMGET, &rts_flag);
	if (value != 0)
		rts_flag |= TIOCM_RTS;
	else
		rts_flag &= ~TIOCM_RTS;
	ioctl(fd, TIOCMSET, &rts_flag);
#endif
}

static
void gc3355_pll_freq_init2(int fd, int pll_freq)
{
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
				gc3355_send_cmds(fd, pll_freq_850M_cmd);
			else
				//0.9v - Scrypt + SHA mode
				gc3355_send_cmds(fd, pll_freq_550M_cmd);
		}
	}
}


void gc3355_open_sha2_unit(int fd, char *opt_sha2_gating)
{
	unsigned char ob_bin[32];
	int i;

	//---sha2 unit---
	char sha2_gating[5][17] =
	{
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
	};
	union
	{
	    unsigned int i32[5];
	    unsigned char c8[20] ;
	}sha2_group;

	int sha2_number=0;
	if (opt_sha2_gating== NULL)
	    sha2_number = 70;
	else
	{
	    if (atoi(opt_sha2_gating) <= 160 && atoi(opt_sha2_gating) >= 0)
			sha2_number = atoi(opt_sha2_gating);
		else
			sha2_number = 70;
	}

	for(i = 0; i < 5; i++)
		sha2_group.i32[i] = 0;

	for(i = 0; i < sha2_number; i++)
		sha2_group.i32[i / 32] += 1 << ( i % 32);

	for(i = 0; i < 20; i++)
		sprintf(&sha2_gating[i / 4][8 + (i % 4) * 2], "%02x", sha2_group.c8[i]);
	//---sha2 unit end---

	for(i = 0; i < 5; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		if (sha2_gating[i][0] == '\0')
			break;

		hex2bin(ob_bin, sha2_gating[i], sizeof(ob_bin));
		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}

	opt_sha2_number = sha2_number;
}

static
void gc3355_open_sha2_unit_single(int fd, unsigned int index)
{
	unsigned char ob_bin[32];
	int i;

	//---sha2 unit---
	char sha2_gating[5][17] =
	{
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
	};
	union
	{
	    unsigned int i32[5];
	    unsigned char c8[20];
	}sha2_group;

	for(i = 0; i < 5; i++)
		sha2_group.i32[i] = 0;

    index = index%160;

	sha2_group.i32[index / 32] += 1 << (index % 32);

	for(i = 0; i < 20; i++)
		sprintf(&sha2_gating[i / 4][8 + (i % 4) * 2], "%02x", sha2_group.c8[i]);
	//---sha2 unit end---

	for(i = 0; i < 5; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		if (sha2_gating[i][0] == '\0')
			break;

		hex2bin(ob_bin, sha2_gating[i], sizeof(ob_bin));
		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
}

static
void gc3355_open_sha2_unit_one_by_one(int fd, char *opt_sha2_gating)
{
	int unit_count = 0;
	unsigned char ob_bin[32];
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
			memset(ob_bin, 0, sizeof(ob_bin));
			hex2bin(ob_bin, sha2_single_open[i], sizeof(ob_bin));
			icarus_write(fd, ob_bin, 8);
			usleep(DEFAULT_DELAY_TIME * 2);
		}
		opt_sha2_number = unit_count;
	}
	else if (unit_count == 0)
		gc3355_send_cmds(fd, sha2_gating);
}

void gc3355_opt_scrypt_only_init(int fd)
{
	gc3355_send_cmds(fd, scrypt_only_init);

	gc3355_pll_freq_init2(fd, opt_pll_freq);
}


void gc3355_open_scrypt_unit(int fd, int status)
{
	const char *scrypt_only_ob[] =
	{
		"55AA1F2810000000",
		"",
	};

	const char *scrypt_ob[] =
	{
		"55AA1F2814000000",
		"",
	};

	unsigned char ob_bin[32];
	int i = 0;

	if (status == SCRYPT_UNIT_OPEN)
	{
		if (opt_dual_mode)
			gc3355_opt_scrypt_init(fd);
		else
			gc3355_opt_scrypt_only_init(fd);
	}
	else
	{
		if (opt_dual_mode)
			gc3355_send_cmds(fd, scrypt_ob);
		else
			gc3355_send_cmds(fd, scrypt_only_ob);
	}
}

void gc3355_dualminer_init(int fd)
{

	const char *init_ob[] =
	{
#if 1
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
#endif
		"55AAEF3020000000",
		"55AA1F2817000000",
		""
	};
	const char *initscrypt_ob[] =
	{
		"55AA1F2814000000",
		"55AA1F2817000000",
		""
	};

	if (opt_scrypt)
		gc3355_send_cmds(fd, initscrypt_ob);
	else
		gc3355_send_cmds(fd, init_ob);

	if (!opt_scrypt)
		gc3355_pll_freq_init2(fd, opt_pll_freq);
}

void gc3355_init_usbstick(int fd, char *sha2_unit, bool is_scrypt_only)
{
	if (gc3355_get_cts_status(fd) == 1)
	{
		//1.2v - Scrypt mode
		if (opt_scrypt)
		{
			if (is_scrypt_only)
				gc3355_opt_scrypt_only_init(fd);
		}
		else
		{
			if (opt_hubfans)
				((sha2_unit == NULL) ? gc3355_open_sha2_unit_one_by_one(fd, HUBFANS_1_2V_sha2) : gc3355_open_sha2_unit_one_by_one(fd, sha2_unit));
			else
				((sha2_unit == NULL) ? gc3355_open_sha2_unit_one_by_one(fd, DEFAULT_1_2V_sha2) : gc3355_open_sha2_unit_one_by_one(fd, sha2_unit));
		}
	}
	else
	{
		//0.9v - Scrypt + SHA mode
		if (opt_scrypt)
		{
			if (is_scrypt_only)
				gc3355_opt_scrypt_only_init(fd);
		}
		else
		{
			if (opt_hubfans)
				((sha2_unit == NULL) ? gc3355_open_sha2_unit_one_by_one(fd, HUBFANS_0_9V_sha2) : gc3355_open_sha2_unit_one_by_one(fd, sha2_unit));
			else
				((sha2_unit == NULL) ? gc3355_open_sha2_unit_one_by_one(fd, DEFAULT_0_9V_sha2) : gc3355_open_sha2_unit_one_by_one(fd, sha2_unit));
		}
	}
}
