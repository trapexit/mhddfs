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

#define _XOPEN_SOURCE   600
#define _POSIX_C_SOURCE 200112L
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <alloca.h>

#ifndef WITHOUT_XATTR
#include <attr/xattr.h>
#endif

#include "parse_options.h"
#include "tools.h"

#include "debug.h"

#include "khash.h"

KHASH_SET_INIT_STR(str)

// getattr
static int
mhdd_stat(const char  *fuse_path,
          struct stat *buf)
{
  int rv;
  char real_path[PATH_MAX];

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  mhdd_debug(MHDD_MSG,
             "mhdd_stat: fuse_path: %s; real_path: %s\n",
             fuse_path, real_path);

  rv = lstat(real_path,buf);
  if(rv == -1)
    return -errno;

  return rv;
}

//statvfs
static int
mhdd_statfs(const char     *fuse_path,
            struct statvfs *stat)
{
  int i;
  int rv;
  struct statvfs devstats;
  struct statvfs tmpstats;

  mhdd_debug(MHDD_MSG,
             "mhdd_statfs: fuse_path: %s\n",
             fuse_path);

  rv = fstatvfs(mhdd.device_fds[0],&devstats);
  if(rv != 0)
    return -errno;

  normalize_statvfs(&devstats,mhdd.min_bsize,mhdd.min_frsize,mhdd.namemax);

  for(i = 1; i < mhdd.device_count; i++)
    {
      rv = fstatvfs(mhdd.device_fds[i],&tmpstats);
      if(rv != 0)
        return -errno;

      normalize_statvfs(&tmpstats,mhdd.min_bsize,mhdd.min_frsize,mhdd.namemax);
      merge_statvfs(&devstats,&tmpstats);
    }

  memcpy(stat,&devstats,sizeof(struct statvfs));
  
  return 0;
}

static int
mhdd_readdir(const char            *dirname,
             void                  *buf,
             fuse_fill_dir_t        filler,
             off_t                  offset,
             struct fuse_file_info *fi)
{
  int i;
  int dirsfound;
  int othersfound;
  char **dirs;
  struct stat st;
  char real_path[PATH_MAX];

  mhdd_debug(MHDD_MSG, "mhdd_readdir: %s\n", dirname);

  dirs = (char **)alloca((mhdd.dir_count+1) * sizeof(char *));

  // find all dirs, ignore those that aren't
  dirsfound   = 0;
  othersfound = 0;
  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_real_path(mhdd.dirs[i], dirname, real_path, PATH_MAX);
      if(stat(real_path, &st) == 0)
        {
          if(S_ISDIR(st.st_mode))
            dirs[dirsfound++] = strdupa(real_path);
          else
            othersfound++;
        }
    }

  dirs[dirsfound] = NULL;

  // dirs not found
  if(dirsfound == 0)
    return (othersfound > 0 ? -ENOTDIR : -ENOENT);

  // read directories
  khash_t(str) *ht = kh_init(str);  
  for(i = 0; dirs[i] != NULL; i++)
    {
      DIR *dh;
      struct dirent *de;

      dh = opendir(dirs[i]);
      if(!dh)
        continue;

      while((de = readdir(dh)))
        {
          int rv;
          char *dup;

          dup = strdup(de->d_name);
          kh_put(str,ht,dup,&rv);
          if(rv == 0)
            continue;
        
          struct stat st;
          char object_name[PATH_MAX];
          create_real_path(dirs[i], de->d_name, object_name, PATH_MAX);

          if(lstat(object_name, &st) == -1)
            {
              khiter_t iter;
              iter = kh_get(str,ht,de->d_name);
              kh_del(str,ht,iter);
              continue;
            }

          filler(buf,de->d_name,&st,0);
        }
    
      closedir(dh);
    }

  khiter_t iter;
  for(iter = kh_begin(ht); iter != kh_end(ht); iter++)
    if(kh_exist(ht,iter))
      free((void*)kh_key(ht,iter));

  kh_destroy(str,ht);

  return 0;
}

// readlink
static int
mhdd_readlink(const char *fuse_path,
              char       *buf,
              size_t      size)
{
  int rv;
  char real_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG, "mhdd_readlink: %s, size = %d\n", real_path, size);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  memset(buf, 0, size);
  rv = readlink(real_path, buf, size);
  if(rv == -1)
    return -errno;

  return rv;
}

#define CREATE_FUNCTION 0
#define OPEN_FUNCION    1
// create or open
static int
mhdd_internal_open(const char            *fuse_path,
                   mode_t                 mode,
                   struct fuse_file_info *fi,
                   int                    what)
{
  int dir_id, fd;  
  char real_path[PATH_MAX];
  
  if(find_real_path(fuse_path,real_path,PATH_MAX) != NULL)
    {
      if(what == CREATE_FUNCTION)
        fd = open(real_path, fi->flags, mode);
      else
        fd = open(real_path, fi->flags);

      if(fd == -1)
        return -errno;

      {
        fileinfo_t *fileinfo = calloc(1,sizeof(fileinfo_t));

        fileinfo->fd        = fd;
        fileinfo->flags     = fi->flags;
        fileinfo->real_path = strdup(real_path);

        fi->fh = (uint64_t)fileinfo;
      }

      mhdd_debug(MHDD_MSG,
                 "mhdd_internal_open: "
                 "fuse_path: %s; real_path: %s; fd: %d; handle: %lld; flags: 0x%X\n",
                 fuse_path, real_path, fd, fi->fh, fi->flags);

      return 0;
    }

  if((dir_id = get_free_dir()) < 0)
    return -ENOSPC;

  create_parent_dirs(dir_id, fuse_path);
  create_real_path(mhdd.dirs[dir_id], fuse_path, real_path, PATH_MAX);

  fd = (what == CREATE_FUNCTION) ?
    open(real_path,fi->flags,mode) :
    open(real_path,fi->flags);

  if(fd == -1)
    return -errno;

  if(getuid() == 0)
    {
      struct stat st;
      gid_t gid = fuse_get_context()->gid;
      if(fstat(fd, &st) == 0)
        {
          /* parent directory is SGID'ed */
          if(st.st_gid != getgid())
            gid = st.st_gid;
        }

      fchown(fd, fuse_get_context()->uid, gid);
    }

  {
    fileinfo_t *fileinfo = calloc(1,sizeof(fileinfo_t));

    fileinfo->fd        = fd;
    fileinfo->flags     = fi->flags;    
    fileinfo->real_path = strdup(real_path);
    
    fi->fh = (uint64_t)fileinfo;
  }

  mhdd_debug(MHDD_MSG,
             "mhdd_internal_open: "
             "fuse_path: %s; real_path: %s; fd: %d; handle: %lld; flags: 0x%X\n",
             fuse_path, real_path, fd, fi->fh, fi->flags);

  return 0;
}

// create
static int
mhdd_create(const char            *fuse_path,
            mode_t                 mode,
            struct fuse_file_info *fi)
{
  int rv;

  rv = mhdd_internal_open(fuse_path, mode, fi, CREATE_FUNCTION);
  if(rv != 0)
    mhdd_debug(MHDD_MSG,"mhdd_create: error: %s\n", strerror(-rv));
  
  return rv;
}

// open
static int
mhdd_open(const char            *fuse_path,
          struct fuse_file_info *fi)
{
  int rv;
  
  rv = mhdd_internal_open(fuse_path, 0, fi, OPEN_FUNCION);
  if(rv != 0)
    mhdd_debug(MHDD_MSG,"mhdd_open: error: %s\n", strerror(-rv));

  return rv;
}

// close
static int
mhdd_release(const char            *fuse_path,
             struct fuse_file_info *fi)
{
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  mhdd_debug(MHDD_MSG,
             "mhdd_release: "
             "fuse_path: %s; real_path: %s; fd: %d; handle: %lld\n",
             fuse_path, fileinfo->real_path, fileinfo->fd, fi->fh);

  if(fileinfo == NULL)
    {
      mhdd_debug(MHDD_MSG,
                 "mhdd_release: unknown file number: %llu\n",
                 fi->fh);
      return -EBADF;
    }
  
  free(fileinfo->real_path);
  close(fileinfo->fd);
  free(fileinfo);

  return 0;
}

// read
static int
mhdd_read(const char            *fuse_path,
          char                  *buf,
          size_t                 count,
          off_t                  offset,
          struct fuse_file_info *fi)
{
  ssize_t     rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  mhdd_debug(MHDD_MSG,
             "mhdd_read: "
             "fuse_path: %s; real_path: %s; fd: %d; handle: %lld; "
             "offset: %lld; count: %lld\n",
             fuse_path, fileinfo->real_path, fileinfo->fd, fi->fh,
             (long long)offset, (long long)count);

  rv = pread(fileinfo->fd, buf, count, offset);
  if(rv == -1)
    return -errno;

  return rv;
}

// write
static int
mhdd_write(const char            *fuse_path,
           const char            *buf,
           size_t                 count,
           off_t                  offset,
           struct fuse_file_info *fi)
{
  ssize_t rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  mhdd_debug(MHDD_MSG,
             "mhdd_write: "
             "fuse_path: %s; real_path: %s; fd: %d; handle = %lld; "
             "offset: %lld; count: %lld\n",
             fuse_path, fileinfo->real_path, fileinfo->fd, fi->fh,
             (long long)offset, (long long)count);

  if(fileinfo == NULL)
    return -EBADF;
  
  rv = pwrite(fileinfo->fd, buf, count, offset);
  if(rv == -1)
    return -errno;

  return rv;
}

static int 
mhdd_ioctl(const char            *fuse_path,
           int                    cmd,
           void                  *arg,
           struct fuse_file_info *fi,
           unsigned int           flags,
           void                  *data)
{
  int rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;
   
  mhdd_debug(MHDD_MSG,
             "mhdd_ioctl: %s, cmd = %i, arg = %p\n",
             fuse_path, cmd, arg);

  if(fileinfo == NULL)
    return -EBADF;
  
  switch(cmd)
    {
    case FS_IOC_GETFLAGS:
      rv = ioctl(fileinfo->fd,FS_IOC_GETFLAGS,data);
      if(rv == -1)
        return -errno;
      break;

    case FS_IOC_SETFLAGS:
      {
        struct fuse_context *fc;

        fc = fuse_get_context();
        rv = ioctl_setflags(fileinfo->fd,fc->pid,data);
        if(rv == -1)
          return -errno;
      }
      break;
        
    default:
      return -ENOTTY;
    }
  
  return 0;	
}

// truncate
static int
mhdd_truncate(const char *fuse_path,
              off_t       size)
{
  int rv;
  char real_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_truncate: %s size = %d\n",
             fuse_path, size);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  rv = truncate(real_path,size);
  if(rv == -1)
    return -errno;

  return rv;
}

// ftrucate
static int
mhdd_ftruncate(const char            *fuse_path,
               off_t                  size,
               struct fuse_file_info *fi)
{
  int rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  mhdd_debug(MHDD_MSG,
             "mhdd_ftruncate: %s, handle = %lld\n",
             fuse_path, fi->fh);
  
  if(fileinfo == NULL)
    return -EBADF;
    
  rv = ftruncate(fileinfo->fd, size);
  if(rv == -1)
    return -errno;

  return rv;
}

// access
static int
mhdd_access(const char *fuse_path,
            int         mask)
{
  int rv;
  uid_t uid;
  gid_t gid;
  struct fuse_context* fc;
  char real_path[PATH_MAX];

  mhdd_debug(MHDD_MSG,
             "mhdd_access: %s mode = %04X\n",
             fuse_path, mask);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;
    
  fc = fuse_get_context();
  
  uid = getuid();
  gid = getgid();
  
  setegid(fc->gid);
  seteuid(fc->uid);
  
  rv = eaccess(real_path, mask);
  
  seteuid(uid);
  seteuid(gid);
  
  if(rv == -1)
    return -errno;
  
  return rv;
}

// mkdir
static int
mhdd_mkdir(const char *fuse_path,
           mode_t      mode)
{
  int rv;
  int dir_id;
  char real_path[PATH_MAX];
  char parent_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_mkdir: fuse_path: %s; mode: %04X\n",
             fuse_path, mode);

  if(find_real_path_id(fuse_path) != -1)
    return -EEXIST;

  if(dirname(fuse_path, parent_path, PATH_MAX) == NULL)
    return -EFAULT;

  if(find_real_path_id(parent_path) == -1)
    return -EFAULT;

  dir_id = get_free_dir();
  if(dir_id < 0)
    return -ENOSPC;

  create_parent_dirs(dir_id, fuse_path);
  create_real_path(mhdd.dirs[dir_id], fuse_path, real_path, PATH_MAX);

  rv = mkdir(real_path, mode);
  if(rv == -1)
    return -errno;
    
  if(getuid() == 0)
    {
      struct stat st;
      gid_t gid = fuse_get_context()->gid;
      if(lstat(real_path, &st) == 0)
        {
          /* parent directory is SGID'ed */
          if(st.st_gid != getgid())
            gid = st.st_gid;
        }

      chown(real_path, fuse_get_context()->uid, gid);
    }
  
  return rv;
}

// rmdir
static int
mhdd_rmdir(const char *fuse_path)
{
  int rv;
  char real_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_rmdir: %s\n",
             fuse_path);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  rv = rmdir(real_path);
  if(rv == -1)
    return -errno;

  return 0;
}

// unlink
static int
mhdd_unlink(const char *fuse_path)
{
  int rv;
  char real_path[PATH_MAX];

  mhdd_debug(MHDD_MSG,
             "mhdd_unlink: %s\n",
             fuse_path);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  rv = unlink(real_path);
  if(rv == -1)
    return -errno;

  return rv;
}

// rename
static int
mhdd_rename(const char *from,
            const char *to)
{
  mhdd_debug(MHDD_MSG, "mhdd_rename: from = %s to = %s\n", from, to);

  int i, rv;
  struct stat sto, sfrom;
  char real_path_from[PATH_MAX];
  char real_path_to[PATH_MAX];
  int from_is_dir = 0, to_is_dir = 0, from_is_file = 0, to_is_file = 0;
  int to_dir_is_empty = 1;

  if(strcmp(from, to) == 0)
    return 0;

  /* seek for possible errors */
  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_real_path(mhdd.dirs[i], to,   real_path_to,   PATH_MAX);
      create_real_path(mhdd.dirs[i], from, real_path_from, PATH_MAX);
      if(stat(real_path_to, &sto) == 0)
        {
          if(S_ISDIR(sto.st_mode))
            {
              to_is_dir++;
              if(!dir_is_empty(real_path_to))
                to_dir_is_empty = 0;
            }
          else
            to_is_file++;
        }

      if(stat(real_path_from, &sfrom) == 0)
        {
          if(S_ISDIR (sfrom.st_mode))
            from_is_dir++;
          else
            from_is_file++;
        }

      if(to_is_file && from_is_dir)
        return -ENOTDIR;
      if(to_is_file && to_is_dir)
        return -ENOTEMPTY;
      if(from_is_dir && !to_dir_is_empty)
        return -ENOTEMPTY;
    }

  /* parent 'to' path doesn't exists */
  {
    char parent_to_path[PATH_MAX];

    if(dirname(to,parent_to_path,PATH_MAX) == NULL)
      return -EFAULT;
     
    if(find_real_path_id(parent_to_path) == -1)
      return -ENOENT;
  }

  /* rename cycle */
  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_real_path(mhdd.dirs[i], to,   real_path_to,   PATH_MAX);
      create_real_path(mhdd.dirs[i], from, real_path_from, PATH_MAX);

      if(stat(real_path_from, &sfrom) == 0)
        {
          /* if from is dir and at the same time file,
             we only rename dir */
          if(from_is_dir && from_is_file)
            {
              if(!S_ISDIR(sfrom.st_mode))
                continue;
            }

          create_parent_dirs(i, to);

          mhdd_debug(MHDD_MSG, "mhdd_rename: rename %s -> %s\n",
                     real_path_from, real_path_to);
          rv = rename(real_path_from, real_path_to);
          if(rv == -1) 
            return -errno;
        }
      else
        {
          /* from and to are files, so we must remove to files */
          if(from_is_file && to_is_file && !from_is_dir)
            {
              if(stat(real_path_to, &sto) == 0)
                {
                  mhdd_debug(MHDD_MSG,"mhdd_rename: unlink %s\n",real_path_to);
                  if(unlink(real_path_to) == -1)
                    return -errno;
                }
            }
        }
    }
  
  return 0;
}

static int
mhdd_utimens(const char            *fuse_path,
             const struct timespec  ts[2])
{
  int rv;  
  char real_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_utimens: %s\n",
             fuse_path);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  rv = utimensat(0, real_path, ts, AT_SYMLINK_NOFOLLOW);
  if(rv == -1)
    return -errno;

  return rv;
}

// .chmod
static int
mhdd_chmod(const char *fuse_path,
           mode_t      mode)
{
  int rv;
  char real_path[PATH_MAX];

  mhdd_debug(MHDD_MSG,
             "mhdd_chmod: fuse_path: %s; mode: 0x%03X\n",
             fuse_path, mode);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;
  
  rv = chmod(real_path, mode);
  if(rv == -1)
    return -errno;
  
  return rv;
}

// chown
static int
mhdd_chown(const char *fuse_path,
           uid_t       uid,
           gid_t       gid)
{
  int rv;
  char real_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_chown: fuse_path: %s; pid: 0x%03X; gid: %03X\n",
             fuse_path, uid, gid);

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;
  
  rv = lchown(real_path, uid, gid);
  if(rv == -1)
    return -errno;

  return rv;
}

// symlink
static int
mhdd_symlink(const char *from,
             const char *to)
{
  int rv;
  int dir_id;
  char real_path[PATH_MAX];
  char parent_path[PATH_MAX];

  mhdd_debug(MHDD_MSG,
             "mhdd_symlink: from = %s to = %s\n",
             from, to);

  if(dirname(to,parent_path,PATH_MAX) == NULL)
    return -ENOENT;

  dir_id = find_real_path_id(parent_path);
  if(dir_id == -1)
    return -ENOENT;

  create_real_path(mhdd.dirs[dir_id],to,real_path,PATH_MAX);
  rv = symlink(from,real_path);
  if(rv == 0)
    return 0;
  else if(errno != ENOSPC)
    return -errno;

  dir_id = get_free_dir();
  if(dir_id == -1)
    return -ENOSPC;

  create_parent_dirs(dir_id,to);
  create_real_path(mhdd.dirs[dir_id],to,real_path,PATH_MAX);

  rv = symlink(from,real_path);
  if(rv == -1)
    return -errno;

  return rv;
}

// link
static int
mhdd_link(const char *from,
          const char *to)
{
  int rv;
  int dir_id;
  
  mhdd_debug(MHDD_MSG,
             "mhdd_link: from: %s; to: %s\n",
             from, to);

  dir_id = find_real_path_id(from);
  if(dir_id == -1)
    return -ENOENT;

  rv = create_parent_dirs(dir_id, to);
  if(rv == -1)
    return -errno;

  char real_path_from[PATH_MAX];
  char real_path_to[PATH_MAX];
  
  create_real_path(mhdd.dirs[dir_id], from, real_path_from, PATH_MAX);
  create_real_path(mhdd.dirs[dir_id], to,   real_path_to,   PATH_MAX);

  rv = link(real_path_from, real_path_to);
  if(rv == -1 )
    return -errno;

  return rv;
}

// mknod
static int
mhdd_mknod(const char *fuse_path,
           mode_t      mode,
           dev_t       rdev)
{
  int rv, i;
  int dir_id;
  char real_path[PATH_MAX];
  char fuse_parent_path[PATH_MAX];
  
  mhdd_debug(MHDD_MSG,
             "mhdd_mknod: fuse_path: %s; mode: %X; rdev: %X\n",
             fuse_path, mode, rdev);

  if(dirname(fuse_path,fuse_parent_path,PATH_MAX) == NULL)
    return -ENOENT;
  
  dir_id = find_real_path_id(fuse_parent_path);
  if(dir_id == -1)
    return -ENOENT;

  for(i = 0; i < 2; i++)
    {
      if(i)
        {
          if((dir_id = get_free_dir()) < 0)
            return -ENOSPC;

          create_parent_dirs(dir_id, fuse_path);
        }

      create_real_path(mhdd.dirs[dir_id], fuse_path, real_path, PATH_MAX);

      if(S_ISREG(mode))
        {
          rv = open(real_path, O_CREAT | O_EXCL | O_WRONLY, mode);
          if(rv >= 0)
            rv = close(rv);
        }
      else if(S_ISFIFO(mode))
        {
          rv = mkfifo(real_path, mode);
        }
      else
        {
          rv = mknod(real_path, mode, rdev);
        }

      if(rv != -1)
        {
          if(getuid() == 0)
            {
              struct fuse_context * fcontext = fuse_get_context();
              chown(real_path, fcontext->uid, fcontext->gid);
            }

          return 0;
        }

      if(errno != ENOSPC)
        return -errno;
    }

  return -errno;
}

#if _POSIX_SYNCHRONIZED_IO + 0 > 0 || defined(__FreeBSD__)
#undef HAVE_FDATASYNC
#else
#define HAVE_FDATASYNC 1
#endif

//fsync
static int
mhdd_fsync(const char            *fuse_path,
           int                    isdatasync,
           struct fuse_file_info *fi)
{
  int rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  mhdd_debug(MHDD_MSG,
             "mhdd_fsync: path = %s handle = %llu\n",
             fuse_path, fi->fh);

  if(fileinfo == NULL)
    {
      errno = EBADF;
      return -errno;
    }

#ifdef HAVE_FDATASYNC
  if(isdatasync)
    rv = fdatasync(fileinfo->fd);
  else
#endif
    rv = fsync(fileinfo->fd);

  if(rv == -1)
    return -errno;

  return rv;
}

// Define extended attribute support

#ifndef WITHOUT_XATTR
static int
mhdd_setxattr(const char *fuse_path,
              const char *attrname,
              const char *attrval,
              size_t      attrvalsize,
              int         flags)
{
  int rv;
  char real_path[PATH_MAX];
  
  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  mhdd_debug(MHDD_MSG,
             "mhdd_setxattr: path = %s name = %s value = %s size = %d\n",
             real_path, attrname, attrval, attrvalsize);

  rv = setxattr(real_path, attrname, attrval, attrvalsize, flags);
  if(rv == -1)
    return -errno;

  return rv;
}
#endif

#ifndef WITHOUT_XATTR
static int
mhdd_getxattr(const char *fuse_path,
              const char *attrname,
              char       *buf,
              size_t      count)
{
  int rv;
  char real_path[PATH_MAX];

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  mhdd_debug(MHDD_MSG,
             "mhdd_getxattr: path = %s name = %s bufsize = %d\n",
             real_path, attrname, count);

  rv = getxattr(real_path, attrname, buf, count);
  if(rv == -1)
    return -errno;

  return rv;
}
#endif

#ifndef WITHOUT_XATTR
static int
mhdd_listxattr(const char *fuse_path,
               char       *buf,
               size_t      count)
{
  int rv;
  char real_path[PATH_MAX];
  
  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;
  
  mhdd_debug(MHDD_MSG,
             "mhdd_listxattr: path = %s bufsize = %d\n",
             real_path, count);

  rv = listxattr(real_path, buf, count);
  if(rv == -1)
    return -errno;

  return rv;
}
#endif

#ifndef WITHOUT_XATTR
static int
mhdd_removexattr(const char *fuse_path,
                 const char *attrname)
{
  int rv;
  char real_path[PATH_MAX];

  if(find_real_path(fuse_path,real_path,PATH_MAX) == NULL)
    return -ENOENT;

  mhdd_debug(MHDD_MSG,
             "mhdd_removexattr: path = %s name = %s\n",
             real_path, attrname);

  rv = removexattr(real_path, attrname);
  if(rv == -1)
    return -errno;
  return 0;
}
#endif

static int
mhdd_fallocate(const char            *fuse_path,
               int                    mode,
               off_t                  offset,
               off_t                  len,
               struct fuse_file_info *fi)
{
  int rv;
  fileinfo_t *fileinfo = (fileinfo_t*)fi->fh;

  rv = myfallocate(fileinfo->fd,mode,offset,len);
  if(rv == -1)
    return -errno;

  return rv;
}
               

// functions links
static struct fuse_operations mhdd_oper =
  {
    .getattr     = mhdd_stat,
    .fgetattr    = NULL, 
    .statfs      = mhdd_statfs,
    .readdir     = mhdd_readdir,
    .readlink    = mhdd_readlink,
    .open        = mhdd_open,
    .release     = mhdd_release,
    .read        = mhdd_read,
    .write       = mhdd_write,
    .create      = mhdd_create,
    .truncate    = mhdd_truncate,
    .ftruncate   = mhdd_ftruncate,
    .access      = mhdd_access,
    .mkdir       = mhdd_mkdir,
    .rmdir       = mhdd_rmdir,
    .unlink      = mhdd_unlink,
    .rename      = mhdd_rename,
    .utimens     = mhdd_utimens,
    .chmod       = mhdd_chmod,
    .chown       = mhdd_chown,
    .symlink     = mhdd_symlink,
    .mknod       = mhdd_mknod,
    .fsync       = mhdd_fsync,
    .link	 = mhdd_link,
    .ioctl       = mhdd_ioctl,
#ifndef WITHOUT_XATTR
    .setxattr    = mhdd_setxattr,
    .getxattr    = mhdd_getxattr,
    .listxattr   = mhdd_listxattr,
    .removexattr = mhdd_removexattr,
#endif
    .fallocate   = mhdd_fallocate
  };


// start
int
main(int   argc,
     char *argv[])
{
  int rv;
  struct fuse_args *args;

  umask(0);

  mhdd_asserts();
  
  mhdd_debug_init();

  args = parse_options(argc, argv);

  rv = fuse_main(args->argc,
                 args->argv,
                 &mhdd_oper,
                 0);

  return rv;
}
