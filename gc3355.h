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

#ifndef bfgminer_gc3355_h
#define bfgminer_gc3355_h

#include <stdbool.h>
#include <stdint.h>

#include "miner.h"

// GridSeed common code begins here

#define GC3355_ORB_SM_DEFAULT_FREQUENCY		600
#define GC3355_STICK_DM_DEFAULT_FREQUENCY	550
#define GC3355_STICK_SM_DEFAULT_FREQUENCY	850

extern
uint32_t gc3355_get_firmware_version(int fd);

extern
void gc3355_set_pll_freq(int fd, int pll_freq);

// 5-chip GridSeed support begins here

#define GC3355_ORB_DEFAULT_CHIPS			5

#define GC3355_READ_SIZE					12
#define GRIDSEED_HASH_SPEED					0.0851128926	// in ms

// static information
struct gc3355_info
{
	uint16_t freq;
	int chips;
};

// dynamic information
struct gc3355_state
{
	struct timeval scanhash_time;
};

#define gc3355_open(path)  serial_open(path, 115200, 1, true)
#define gc3355_close(fd)  serial_close(fd)

extern
int gc3355_read(int fd, char *buf, size_t size);

extern
ssize_t gc3355_write(int fd, const void * const buf, const size_t size);

extern
void gc3355_init_usborb(struct cgpu_info *device);

extern
void gc3355_scrypt_reset(struct cgpu_info *device);


// 1-chip DualMiner support begins here

extern
char *opt_dualminer_sha2_gating;

extern
int opt_pll_freq;

//once this is made an option, needs to be >= 0 and <= 160
//already enforced in gc3355 but no stdout yet
extern
int opt_sha2_number;

//mining both Scrypt & SHA2 at the same time with two processes
//SHA2 process must be run first, no arg requirements, first serial port will be used
//Scrypt process must be launched after, --scrypt and --dual-mode args required
extern
bool opt_dual_mode;

extern
void gc3355_sha2_init(int fd);

extern
void gc3355_scrypt_init(int fd);

extern
void gc3355_scrypt_only_init(int fd);

extern
void gc3355_dualmode_init(int fd);

extern
void gc3355_scrypt_restart(int fd);

extern
void gc3355_init_usbstick(int fd, char *sha2_unit);

extern
void gc3355_open_scrypt_unit(int fd, int status);

#define gc3355_get_cts_status(fd)  (get_serial_cts(fd) ? 0 : 1)
#define gc3355_set_rts_status(fd, val)  set_serial_rts(fd, val)
#define gc3355_set_dtr_status(fd, val)  set_serial_dtr(fd, val)

#endif
