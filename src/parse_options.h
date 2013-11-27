/*
  mhddfs - Multi HDD [FUSE] File System
  Copyright (C) 2008 Dmitry E. Oboukhov <dimka@avanto.org>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef __PARSE__OPTIONS__H__
#define __PARSE__OPTIONS__H__

#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <fuse.h>

#define DEFAULT_MOVE_LIMIT ( 4UL * 1024 * 1024 * 1024 )
#define MINIMUM_MOVE_LIMIT ( 50UL * 1024 * 1024 )

typedef struct mhdd_config_t
{
  char           *mount;
  char          **dirs; 
  uint32_t        dir_count;
  dev_t          *devices;
  int            *device_fds;
  uint32_t        device_count;
  unsigned long   min_bsize;
  unsigned long   min_frsize;
  unsigned long   namemax;
  long            pathmax;
  off_t           move_limit;
  char           *move_limit_str;
  FILE           *debug;
  char           *debug_file;
  int             log_level;
} mhdd_config_t;

extern mhdd_config_t mhdd;

struct fuse_args *
parse_options(int   argc,
              char *argv[]);

#endif
