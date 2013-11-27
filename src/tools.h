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

  Modified by Glenn Washburn <gwashburn@Crossroads.com>
     (added support for extended attributes.)
*/
#ifndef __TOOLS__H__
#define __TOOLS__H__

#include <stdint.h>
#include <pthread.h>

#define MOVE_BLOCK_SIZE     32768

#define strlendupa(s,n)                                                 \
  (__extension__                                                        \
   ({                                                                   \
     const char *__old = (s);                                           \
     *(n) = strlen (__old) + 1;                                         \
     char *__new = (char *) __builtin_alloca (__len);                   \
     (char *) memcpy(__new, __old, __len);                              \
   }))

typedef struct fileinfo_t
{
  int   fd;
  int   flags;
  char *real_path;
} fileinfo_t;

int
get_free_dir(void);

int
create_real_path(const char *dir,
                 const char *file,
                 char       *real_path,
                 const int   maxlen);

int
create_real_tmppath(const char *dir,
                    const char *file,
                    char       *real_path,
                    const int   maxlen);

char*
find_real_path(const char *fuse_path,
               char       *real_path,
               const int   maxlen);

int
find_real_path_id(const char *fuse_path);

int
create_parent_dirs(int dir_id,
                   const char *path);

int
copy_xattrs(const char *from,
            const char *to);

int
move_file(const char *fuse_path,
          fileinfo_t *fileinfo,
          off_t       size);

char*
dirname(char const * const  path,
        char               *parent,
        size_t              maxlen);

int
dir_is_empty(const char *path);

void
normalize_statvfs(struct statvfs      *stat,
                  const unsigned long  min_bsize,
                  const unsigned long  min_frsize,
                  const unsigned long  namemax);

void
merge_statvfs(struct statvfs       * const out,
              const struct statvfs * const in);

int
myfallocate(int   fd,
            int   mode,
            off_t offset,
            off_t len);

int
has_cap_linux_immutable(const pid_t pid);

int
ioctl_setflags(const int    fd,
               const pid_t  pid,
               void        *data);

void
mhdd_asserts();

#endif
