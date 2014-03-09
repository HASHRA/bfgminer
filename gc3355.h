/*
 * Copyright 2014 Nate Woolls
 * Copyright 2014 GridSeed Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef bfgminer_gc3355_h
#define bfgminer_gc3355_h

#include <stdint.h>

#include "miner.h"

#define GC3355_DEFAULT_FREQUENCY	600
#define GC3355_DEFAULT_CHIPS		5

#define GC3355_READ_SIZE			12
#define GRIDSEED_HASH_SPEED			0.0851128926	// in ms

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

extern
int gc3355_open(const char *path);

extern
int gc3355_close(int fd);

extern
int gc3355_read(int fd, char *buf, size_t size);

extern
ssize_t gc3355_write(int fd, const void * const buf, const size_t size);

extern
void gc3355_init(struct cgpu_info *device);

extern
void gc3355_scrypt_reset(struct cgpu_info *device);

extern
void gc3355_set_core_freq(struct cgpu_info *device);

#endif
