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

#define _GNU_SOURCE 1
#define _BSD_SOURCE 1

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stddef.h>
#include <fuse.h>
#include <unistd.h>

#include "parse_options.h"
#include "usage.h"
#include "version.h"
#include "debug.h"
#include "tools.h"

mhdd_config_t mhdd =
  {
    .mount          = NULL,
    .dirs           = NULL,
    .dir_count      = 0,
    .devices        = NULL,
    .device_fds     = NULL,
    .device_count   = 0,
    .min_bsize      = ULONG_MAX,
    .min_frsize     = ULONG_MAX,
    .namemax        = ULONG_MAX,
    .pathmax        = PATH_MAX,
    .move_limit     = DEFAULT_MOVE_LIMIT,
    .move_limit_str = NULL,
    .debug          = NULL,
    .debug_file     = NULL,
    .log_level      = MHDD_DEFAULT_DEBUG_LEVEL
  };

#define MHDDFS_OPT(t, p, v) \
  { t, offsetof(mhdd_config_t, p), v }
#define MHDD_VERSION_OPT 15121974

#if FUSE_VERSION >= 27
#define FUSE_MP_OPT_STR "-osubtype=mhddfs,fsname="
#else
#define FUSE_MP_OPT_STR "-ofsname=mhddfs#"
#endif

static struct fuse_opt mhddfs_opts[] =
  {
    MHDDFS_OPT("mlimit=%s",   move_limit_str, 0),
    MHDDFS_OPT("logfile=%s",  debug_file, 0),
    MHDDFS_OPT("loglevel=%d", log_level, 0),
    
    FUSE_OPT_KEY("-V",        MHDD_VERSION_OPT),
    FUSE_OPT_KEY("--version", MHDD_VERSION_OPT),
    
    FUSE_OPT_END
  };

static void
add_mhdd_device(const char *dir)
{
  struct stat st;
  if(lstat(dir,&st) == 0)
    {
      int i;
      int found = 0;
      for(i = 0; i < mhdd.device_count; i++)
        {
          if(mhdd.devices[i] == st.st_dev)
            {
              found = 1;
              break;
            }
        }
      
      if(!found)
        {
          struct statvfs stats;
          int newdevlen = (sizeof(dev_t) * (mhdd.device_count + 1));
          int newfdlen  = (sizeof(int)   * (mhdd.device_count + 1));          
          
          mhdd.devices    = realloc(mhdd.devices,newdevlen);
          mhdd.device_fds = realloc(mhdd.device_fds,newfdlen);
          mhdd.devices[mhdd.device_count]    = st.st_dev;
          mhdd.device_fds[mhdd.device_count] = open(dir,O_RDONLY);
          if(fstatvfs(mhdd.device_fds[mhdd.device_count],&stats) == 0)
            {
              long limit;

              limit = fpathconf(mhdd.device_fds[mhdd.device_count],
                                _POSIX_PATH_MAX);
              if(limit != -1 && mhdd.pathmax > limit)
                mhdd.pathmax = limit;
              
              if(mhdd.min_bsize > stats.f_bsize)
                mhdd.min_bsize = stats.f_bsize;
              if(mhdd.min_frsize > stats.f_frsize)
                mhdd.min_frsize = stats.f_frsize;
              if(mhdd.namemax > stats.f_namemax)
                mhdd.namemax = stats.f_namemax;
            }

          mhdd.device_count++;
        }
    }
}

static void
add_mhdd_dir(const char *dir)
{
  char *fullpath;
  unsigned int len;
  
  if(dir[0] == '/')
    {
      fullpath = strdup(dir);
    }
  else
    {
      char cpwd[PATH_MAX];
      char real_path[PATH_MAX];
      getcwd(cpwd, PATH_MAX);
      create_real_path(cpwd, dir, real_path, PATH_MAX);
      fullpath = strdup(real_path);
    }

  len = strlen(fullpath) - 1;
  while(fullpath[len] == '/')
    fullpath[len--] = '\0';
  
  mhdd.dirs = realloc(mhdd.dirs,(sizeof(char*)*(mhdd.dir_count+1)));
  mhdd.dirs[mhdd.dir_count++] = fullpath;

  add_mhdd_device(fullpath);
}

static int
mhddfs_opt_proc(void             *data,
                const char       *arg,
                int               key,
                struct fuse_args *outargs)
{
  switch(key)
    {
    case MHDD_VERSION_OPT:
      fprintf(stderr, "mhddfs version: %s\n", VERSION);
      exit(0);

    case FUSE_OPT_KEY_NONOPT:
      {
        char *tmp;
        char *dir = strdupa(arg);

        for(tmp=dir; tmp; tmp=strchr(tmp+1, ','))
          {
            if(*tmp==',')
              tmp++;
            char *add = strdupa(tmp);
            char *end = strchr(add, ',');
            if(end)
              *end = 0;
            add_mhdd_dir(add);
          }

        return 0;
      }
    }
  
  return 1;
}

static void
check_if_unique_mountpoints(void)
{
  int i, j;
  struct stat *stats = alloca(mhdd.dir_count * sizeof(struct stat));

  for(i = 0; i < mhdd.dir_count; i++)
    {
      if(stat(mhdd.dirs[i], stats + i) != 0)
        memset(stats + i, 0, sizeof(struct stat));

      for(j = 0; j < i; j++)
        {
          if(strcmp(mhdd.dirs[i], mhdd.dirs[j]) != 0)
            {
              /*  mountdir isn't unique */
              if(stats[j].st_dev != stats[i].st_dev)
                continue;
              if(stats[j].st_ino != stats[i].st_ino)
                continue;
              if(!stats[i].st_dev)
                continue;
              if(!stats[i].st_ino)
                continue;
            }
          
          fprintf(stderr,
                  "mhddfs: Duplicate directories: %s %s\n"
                  "\t%s was excluded from dirlist\n",
                  mhdd.dirs[i],mhdd.dirs[j],mhdd.dirs[i]);
          
          free(mhdd.dirs[i]);
          mhdd.dirs[i] = 0;
          
          for(j = i; j < mhdd.dir_count - 1; j++)
            mhdd.dirs[j] = mhdd.dirs[j+1];
          mhdd.dir_count--;
          i--;
          break;
        }
    }
}

struct fuse_args*
parse_options(int   argc,
              char *argv[])
{
  struct fuse_args *args = calloc(1, sizeof(struct fuse_args));
  char *info;
  int i,  l;

  {
    struct fuse_args tmp = FUSE_ARGS_INIT(argc, argv);
    memcpy(args, &tmp, sizeof(struct fuse_args));
  }

  if(fuse_opt_parse(args, &mhdd, mhddfs_opts, mhddfs_opt_proc) == -1)
    usage(stderr);

  if(mhdd.dir_count < 3)
    usage(stderr);

  mhdd.mount = mhdd.dirs[--mhdd.dir_count];
  mhdd.dirs[mhdd.dir_count] = NULL;

  check_if_unique_mountpoints();

  for(i = l = 0; i < mhdd.dir_count; i++)
    l += strlen(mhdd.dirs[i]) + 2;
  l += sizeof(FUSE_MP_OPT_STR);

  info = alloca(l * sizeof(char));
  strcat(info, FUSE_MP_OPT_STR);
  for(i = 0; i < mhdd.dir_count; i++)
    {
      if(i)
        strcat(info, ";");
      strcat(info, mhdd.dirs[i]);
    }

  fuse_opt_insert_arg(args, 1, info);
  fuse_opt_insert_arg(args, 1, mhdd.mount);

  if(mhdd.dir_count)
    {
      int i;
      for(i = 0; i < mhdd.dir_count; i++)
        {
          struct stat info;
          if(stat(mhdd.dirs[i], &info))
            {
              fprintf(stderr,
                      "mhddfs: can not stat '%s': %s\n",
                      mhdd.dirs[i], strerror(errno));
              exit(-1);
            }
          if(!S_ISDIR(info.st_mode))
            {
              fprintf(stderr,
                      "mhddfs: '%s' - is not directory\n\n",
                      mhdd.dirs[i]);
              exit(-1);
            }

          fprintf(stderr,
                  "mhddfs: directory '%s' added to list\n",
                  mhdd.dirs[i]);
        }
    }

  fprintf(stderr, "mhddfs: mount to: %s\n", mhdd.mount);

  if(mhdd.debug_file)
    {
      fprintf(stderr, "mhddfs: using debug file: %s, log_level=%d\n",
              mhdd.debug_file, mhdd.log_level);

      mhdd.debug = fopen(mhdd.debug_file, "a");
      if(!mhdd.debug)
        {
          fprintf(stderr, "Can not open file '%s': %s",
                  mhdd.debug_file,
                  strerror(errno));
          exit(-1);
        }
      setvbuf(mhdd.debug, NULL, _IONBF, 0);
    }

  if(mhdd.move_limit_str)
    {
      int len = strlen(mhdd.move_limit_str);

      if(len)
        {
          switch(mhdd.move_limit_str[len-1])
            {
            case 'm':
            case 'M':
              mhdd.move_limit_str[len-1]  = 0;
              mhdd.move_limit             = atoll(mhdd.move_limit_str);
              mhdd.move_limit            *= 1024*1024;
              break;
            case 'g':
            case 'G':
              mhdd.move_limit_str[len-1]  = 0;
              mhdd.move_limit             = atoll(mhdd.move_limit_str);
              mhdd.move_limit            *= 1024*1024*1024;
              break;
              
            case 'k':
            case 'K':
              mhdd.move_limit_str[len-1]  = 0;
              mhdd.move_limit             = atoll(mhdd.move_limit_str);
              mhdd.move_limit            *= 1024;
              break;
              
            case '%':
              mhdd.move_limit_str[len-1] = 0;
              mhdd.move_limit            = atoll(mhdd.move_limit_str);
              break;
              
            default:
              mhdd.move_limit = atoll(mhdd.move_limit_str);
              break;
            }
        }

      if(mhdd.move_limit < MINIMUM_MOVE_LIMIT)
        {
          if(!mhdd.move_limit)
            mhdd.move_limit = DEFAULT_MOVE_LIMIT;
          else if(mhdd.move_limit > 100)
            mhdd.move_limit = MINIMUM_MOVE_LIMIT;
        }
    }

  if(mhdd.move_limit <= 100)
    fprintf(stderr, "mhddfs: move size limit %lld%%\n",
            (long long)mhdd.move_limit);
  else
    fprintf(stderr, "mhddfs: move size limit %lld bytes\n",
            (long long)mhdd.move_limit);

  mhdd_debug(MHDD_MSG, " >>>>> mhdd " VERSION " started <<<<<\n");

  return args;
}
