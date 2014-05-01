/*
 * Copyright 2014 Luke Dashjr
 * Copyright 2014 Nate Woolls
 * Copyright 2014 GridSeed Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <stdbool.h>

#include "deviceapi.h"
#include "lowlevel.h"
#include "lowl-vcom.h"
#include "gc3355.h"

BFG_REGISTER_DRIVER(gridseed_drv)

/*
 * helper functions
 */

static
struct cgpu_info *gridseed_alloc_device(const char *path, struct device_drv *driver, struct gc3355_info *info)
{
	struct cgpu_info *device = calloc(1, sizeof(struct cgpu_info));
	if (unlikely(!device))
		quit(1, "Failed to malloc cgpu_info");

	device->drv = driver;
	device->device_path = strdup(path);
	device->device_fd = -1;
	device->threads = 1;
	device->device_data = info;

	return device;
}

static
struct gc3355_info *gridseed_alloc_info()
{
	struct gc3355_info *info = calloc(1, sizeof(struct gc3355_info));
	if (unlikely(!info))
		quit(1, "Failed to malloc gc3355_info");

	info->freq = GC3355_DEFAULT_FREQUENCY;
  if (opt_gs_chips > 0) {
      info->chips = opt_gs_chips;
      applog(LOG_INFO, "------GS Setting %d chips ", opt_gs_chips);
  }else{
      info->chips = GC3355_DEFAULT_CHIPS;
      applog(LOG_INFO, "------GS Setting chips setting not set, using %d", GC3355_DEFAULT_CHIPS);
  }

	return info;
}

/*
 * device detection
 */

static
bool gridseed_detect_custom(const char *path, struct device_drv *driver, struct gc3355_info *info)
{
	int fd = gc3355_open(path);
	if(fd < 0)
		return false;

	const char detect_cmd[] = "55aac000909090900000000001000000";
	unsigned char detect_data[16];
	int size = sizeof(detect_data);

	hex2bin(detect_data, detect_cmd, size);

	int written = gc3355_write(fd, detect_data, size);
	if (written != size)
	{
		applog(LOG_ERR, "%s: Failed writing work to %s", gridseed_drv.dname, path);
		gc3355_close(fd);
		return false;
	}

	char buf[GC3355_READ_SIZE];
	int read = gc3355_read(fd, buf, GC3355_READ_SIZE);
	if (read != GC3355_READ_SIZE)
	{
		applog(LOG_ERR, "%s: Failed reading work from %s", gridseed_drv.dname, path);
		gc3355_close(fd);
		return false;
	}

	if (memcmp(buf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GC3355_READ_SIZE - 4) != 0)
	{
		applog(LOG_ERR, "%s: Invalid detect response from %s", gridseed_drv.dname, path);
		gc3355_close(fd);
		return false;
	}

	uint32_t fw_version = le32toh(*(uint32_t *)(buf + 8));

	struct cgpu_info *device = gridseed_alloc_device(path, driver, info);

	if (serial_claim_v(path, driver))
		return false;

	if (!add_cgpu(device))
		return false;

	device->device_fd = fd;

	gc3355_init(device);

	applog(LOG_INFO, "Found %"PRIpreprv" at %s", device->proc_repr, path);
	applog(LOG_DEBUG, "%"PRIpreprv": Init: firmware=%d", device->proc_repr, fw_version);

	return true;
}

static
bool gridseed_detect_one(const char *path)
{
	struct gc3355_info *info = gridseed_alloc_info();

	if (!gridseed_detect_custom(path, &gridseed_drv, info))
	{
		free(info);
		return false;
	}
	return true;
}

static
bool gridseed_lowl_probe(const struct lowlevel_device_info * const info)
{
	return vcom_lowl_probe_wrapper(info, gridseed_detect_one);
}

/*
 * setup & shutdown
 */

static
bool gridseed_thread_prepare(struct thr_info *thr)
{
	thr->cgpu_data = calloc(1, sizeof(*thr->cgpu_data));

	struct cgpu_info *device = thr->cgpu;
	device->min_nonce_diff = 1./0x10000;

	return true;
}

static
void gridseed_thread_shutdown(struct thr_info *thr)
{
	struct cgpu_info *device = thr->cgpu;
	gc3355_close(device->device_fd);

	free(thr->cgpu_data);
}

/*
 * mining loop
 */

// send work to the device
static
bool gridseed_prepare_work(struct thr_info __maybe_unused *thr, struct work *work)
{
	struct cgpu_info *device = thr->cgpu;
	struct gc3355_info *info = device->device_data;
	struct gc3355_state * const state = thr->cgpu_data;

	cgtime(&state->scanhash_time);

	gc3355_scrypt_reset(device);

	unsigned char cmd[156];

	memcpy(cmd, "\x55\xaa\x1f\x00", 4);
	memcpy(cmd+4, work->target, 32);
	memcpy(cmd+36, work->midstate, 32);
	memcpy(cmd+68, work->data, 80);
	memcpy(cmd+148, "\xff\xff\xff\xff", 4);  // nonce_max
	memcpy(cmd+152, "\x12\x34\x56\x78", 4);  // taskid

	return (gc3355_write(device->device_fd, cmd, sizeof(cmd)) == sizeof(cmd));
}

// read response (nonce) from the device

static
int64_t gridseed_calc_hashes(struct thr_info *thr)
{
	struct cgpu_info *device = thr->cgpu;
	struct gc3355_state * const state = thr->cgpu_data;
	struct timeval old_scanhash_time = state->scanhash_time;
	cgtime(&state->scanhash_time);
	int elapsed_ms = ms_tdiff(&state->scanhash_time, &old_scanhash_time);

	struct gc3355_info *info = device->device_data;
	return GRIDSEED_HASH_SPEED * (double)elapsed_ms * (double)(info->freq * info->chips);
}

static
int64_t gridseed_scanhash(struct thr_info *thr, struct work *work, int64_t __maybe_unused max_nonce)
{
	struct cgpu_info *device = thr->cgpu;
	struct gc3355_info *info = device->device_data;

	unsigned char buf[GC3355_READ_SIZE];
	int read = 0;
	int fd = device->device_fd;

	while (!thr->work_restart && (read = gc3355_read(fd, (char *)buf, GC3355_READ_SIZE)) > 0)
	{
		if (buf[0] == 0x55 || buf[1] == 0x20)
		{
			uint32_t nonce = *(uint32_t *)(buf+4);
			nonce = le32toh(nonce);
			submit_nonce(thr, work, nonce);
		} else
		{
			applog(LOG_ERR, "%"PRIpreprv": Unrecognized response", device->proc_repr);
			return -1;
		}
	}

	return gridseed_calc_hashes(thr);
}

/*
 * specify settings / options
 */

// support for --set-device dualminer:clock=freq
static
char *gridseed_set_device(struct cgpu_info *device, char *option, char *setting, char *replybuf)
{
	if (strcasecmp(option, "clock") == 0)
	{
		int val = atoi(setting);

		struct gc3355_info *info = device->device_data;
		info->freq = val;
		gc3355_set_core_freq(device);

		return NULL;
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

struct device_drv gridseed_drv =
{
	// metadata
	.dname = "gridseed",
	.name = "GSD",

	// detect device
	.lowl_probe = gridseed_lowl_probe,

	// initialize device
	.thread_prepare = gridseed_thread_prepare,

	// specify mining type - scanhash
	.minerloop = minerloop_scanhash,

	// scanhash mining hooks
	.prepare_work = gridseed_prepare_work,
	.scanhash = gridseed_scanhash,

	// teardown device
	.thread_shutdown = gridseed_thread_shutdown,

	// specify settings / options
	.set_device = gridseed_set_device,
};
