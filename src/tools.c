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

#define _XOPEN_SOURCE 600
#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/capability.h>
#include <errno.h>
#include <utime.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/fs.h>
#include <assert.h>

#ifndef WITHOUT_XATTR
#include <attr/xattr.h>
#endif

#include "tools.h"
#include "debug.h"
#include "parse_options.h"


// get dir idx for maximum free space
int
get_free_dir(void)
{
  int i, max, max_perc, max_perc_space = 0;
  struct statvfs stf;
  fsblkcnt_t max_space = 0;

  for (max = i = 0; i < mhdd.dir_count; i++)
    {
      if(statvfs(mhdd.dirs[i], &stf) != 0)
        continue;

      fsblkcnt_t space = stf.f_bsize * stf.f_bavail;

      if(mhdd.move_limit <= 100)
        {
          int perc;

          if(mhdd.move_limit != 100)
            {
              fsblkcnt_t perclimit = stf.f_blocks;

              if(mhdd.move_limit != 99)
                {
                  perclimit *= mhdd.move_limit + 1;
                  perclimit /= 100;
                }

              if(stf.f_bavail >= perclimit)
                return i;
            }

          perc = 100 * stf.f_bavail / stf.f_blocks;

          if(perc > max_perc_space)
            {
              max_perc_space = perc;
              max_perc = i;
            }
        }
      else
        {
          if(space >= mhdd.move_limit)
            return i;
        }

      if(space > max_space)
        {
          max_space = space;
          max = i;
        }
    }

  if(!max_space && !max_perc_space)
    {
      mhdd_debug(MHDD_INFO,
                 "get_free_dir: Can't find freespace\n");
      return -1;
    }

  if(max_perc_space)
    return max_perc;

  return max;
}

// find mount point with free space > size
// -1 if not found
static int
find_free_space(off_t size)
{
  int i, max;
  struct statvfs stf;
  fsblkcnt_t max_space=0;

  for(max = -1, i = 0; i < mhdd.dir_count; i++)
    {
      if(statvfs(mhdd.dirs[i], &stf) != 0)
        continue;
      
      fsblkcnt_t space = stf.f_bsize * stf.f_bavail;

      if(space > (size + mhdd.move_limit))
        return i;

      if((space > size) &&
         (max < 0 || max_space < space))
        {
          max_space = space;
          max = i;
        }
    }

  return max;
}

static int
reopen_files(fileinfo_t *fileinfo,
             const char *new_real_path)
{
  mhdd_debug(MHDD_INFO,
             "reopen_files: %s -> %s\n",
             fileinfo->real_path, new_real_path);

  int   newfd;
  int   flags    = fileinfo->flags & ~(O_EXCL|O_TRUNC);
  off_t cur_seek = lseek(fileinfo->fd, 0, SEEK_CUR);
  
  newfd = open(new_real_path, flags);
  if(newfd == -1)
    {
      mhdd_debug(MHDD_INFO,
                 "reopen_files: error reopen: %s\n",
                 strerror(errno));
      return -errno;
    }

  if(cur_seek != lseek(newfd, cur_seek, SEEK_SET))
    {
      mhdd_debug(MHDD_INFO,
                 "reopen_files: error seek %s\n",
                 strerror(errno));
      close(newfd);

      return -errno;
    }
      
  if(dup2(newfd, fileinfo->fd) != fileinfo->fd)
    {
      mhdd_debug(MHDD_INFO,
                 "reopen_files: error dup2 %s\n",
                 strerror(errno));
      close(newfd);

      return -errno;
    }

  mhdd_debug(MHDD_MSG,
             "reopen_file: reopened %s (to %s) old h=%x "
             "new h=%x seek=%lld\n",
             fileinfo->real_path, new_real_path, fileinfo->fd, newfd, cur_seek);

  close(newfd);

  free(fileinfo->real_path);
  fileinfo->real_path = strdup(new_real_path);

  return 0;
}

int
move_file(const char *fuse_path,
          fileinfo_t *fileinfo,
          const off_t wsize)
{
  char from[PATH_MAX], to[PATH_MAX], to_tmp[PATH_MAX];
  off_t size;
  int outfd;
  FILE *input, *output;
  int ret, dir_id;
  struct utimbuf ftime = {0};
  struct statvfs svf;
  fsblkcnt_t space;
  struct stat st;

  mhdd_debug(MHDD_MSG,
             "move_file: real_path = %s\n",
             fileinfo->real_path);

  /* TODO: it would be nice to contrive something alter */
  strncpy(from, fileinfo->real_path, PATH_MAX);
  
  /* We need to check if already moved */
  if(statvfs(from, &svf) != 0)
    return -errno;

  space  = svf.f_bsize;
  space *= svf.f_bavail;

  /* get file size */
  if(fstat(fileinfo->fd, &st) != 0)
    {
      mhdd_debug(MHDD_MSG, "move_file: error stat %s: %s\n",
                 from, strerror(errno));
      return -errno;
    }

  /* Hard link support is limited to a single device, and files with
     >1 hardlinks cannot be moved between devices since this would
     (a) result in partial files on the source device (b) not free
     the space from the source device during unlink. */
  if(st.st_nlink > 1)
    {
      mhdd_debug(MHDD_MSG,
                 "move_file: cannot move files with >1 hardlinks\n");
      return -ENOTSUP;
    }

  size = (st.st_size < wsize) ? wsize : st.st_size;
  if(space > size)
    {
      mhdd_debug(MHDD_MSG, "move_file: we have enough space\n");
      return 0;
    }

  if((dir_id = find_free_space(size)) == -1)
    {
      mhdd_debug(MHDD_MSG, "move_file: can not find space\n");
      return -1;
    }

  if(!(input = fopen(from, "r")))
    return -errno;

  create_parent_dirs(dir_id, fuse_path);
  create_real_path(mhdd.dirs[dir_id],    fuse_path, to,     PATH_MAX);
  create_real_tmppath(mhdd.dirs[dir_id], fuse_path, to_tmp, PATH_MAX);

  outfd = mkstemp(to_tmp);
  if(outfd == -1)
    {
      ret = -errno;
      mhdd_debug(MHDD_MSG, "move_file: error create %s: %s\n",
                 to_tmp, strerror(errno));
      fclose(input);
      return ret;
    }

  output = fdopen(outfd,"w+");
  if(output == NULL)
    {
      ret = -errno;
      mhdd_debug(MHDD_MSG, "move_file: error create %s: %s\n",
                 to_tmp, strerror(errno));
      close(outfd);
      fclose(input);
      return ret;
    }

  mhdd_debug(MHDD_MSG, "move_file: move %s to %s\n", from, to_tmp);

  // move data
  {
    char buf[MOVE_BLOCK_SIZE];
    
    while((size = fread(buf, sizeof(char), MOVE_BLOCK_SIZE, input)))
      {
        if(size != fwrite(buf, sizeof(char), size, output))
          {
            mhdd_debug(MHDD_MSG,
                       "move_file: error move data to %s: %s\n",
                       to_tmp, strerror(errno));
            fclose(output);
            fclose(input);
            unlink(to_tmp);
            return -1;
          }
      }
  }

  fclose(input);  
  mhdd_debug(MHDD_MSG, "move_file: done move data\n");

  // owner/group/permissions
  fchmod(outfd, st.st_mode);
  fchown(outfd, st.st_uid, st.st_gid);
  fclose(output);

#ifndef WITHOUT_XATTR
  // extended attributes
  if(copy_xattrs(from, to_tmp) == -1)
    mhdd_debug(MHDD_MSG,
               "copy_xattrs: error copying xattrs from %s to %s\n",
               from, to_tmp);
#endif

  // time
  ftime.actime = st.st_atime;
  ftime.modtime = st.st_mtime;
  utime(to_tmp, &ftime);

  ret = rename(to_tmp, to);
  if(ret == -1)
    {
      unlink(to_tmp);
      return -1;
    }
  
  ret = reopen_files(fileinfo, to);
  if(ret == 0)
    unlink(from);      
  else
    unlink(to);

  mhdd_debug(MHDD_MSG,
             "move_file: %s -> %s: done, code=%d\n",
             from, to, ret);

  return ret;
}

#ifndef WITHOUT_XATTR
static int
my_getxattr(const char  *path,
            const char  *name,
            void       **value,
            size_t      *size)
{
  int rv;

  if(*size != 0)
    rv = getxattr(path, name, *value, *size);
  else
    (rv = -1,errno = ERANGE);
  
  if(rv == -1 && errno == ERANGE)
    {
      rv = getxattr(path,name,NULL,0);
      if(rv == -1)
        return -1;

      {
        void *new_value;
        
        new_value = realloc(*value,rv);
        if(new_value == NULL)
          return -1;
        
        *size  = rv;
        *value = new_value;
        
        return my_getxattr(path,name,value,size);
      }
    }
      
  return rv;
}

static int
my_listxattr(const char  *path,
             char       **list,
             size_t      *size)
{
  int rv;

  if(*size != 0)
    rv = listxattr(path,*list,*size);
  else
    (rv = -1,errno = ERANGE);
    
  if(rv == -1 && errno == ERANGE)
    {
      rv = listxattr(path,NULL,0);
      if(rv == -1)
        return -1;

      {
        void *new_value;

        new_value = realloc(*list,rv);
        if(new_value == NULL)
          return -1;

        *size = rv;
        *list = new_value;

        return my_listxattr(path,list,size);
      }
    }
  
  return rv;
}

int
copy_xattrs(const char *from,
            const char *to)
{
  int     rv;
  size_t  listbufsize;
  size_t  attrvalsize;
  char   *listbuf;
  char   *attrvalbuf;
  char   *name_begin;
  char   *name_end;

  listbufsize = mhdd.namemax;
  listbuf     = (char*)calloc(1,listbufsize);
  rv = my_listxattr(from,&listbuf,&listbufsize);
  if(rv == -1)
    {
      mhdd_debug(MHDD_MSG,
                 "listxattr: error listing xattrs on %s : %s\n",
                 from, strerror(errno));
      return -1;
    }

  attrvalsize = mhdd.namemax;
  attrvalbuf  = (char*)malloc(attrvalsize);
  for(name_begin = listbuf, name_end = listbuf + 1;
      name_end < (listbuf + listbufsize); name_end++)
    {
      if(*name_end != '\0')
        continue;

      rv = my_getxattr(from, name_begin, (void**)&attrvalbuf, &attrvalsize);
      if(rv == -1)
        {
          mhdd_debug(MHDD_MSG,
                     "getxattr: error getting xattr value on %s name %s : %s\n",
                     from, name_begin, strerror(errno));
          return -1;
        }

      // set the value of the extended attribute on dest file
      rv = setxattr(to, name_begin, attrvalbuf, attrvalsize, 0);
      if(rv == -1)
        {
          mhdd_debug(MHDD_MSG,
                     "setxattr: error setting xattr value on %s name %s : %s\n",
                     from, name_begin, strerror(errno));
          return -1;
        }

      // point the pointer to the start of the attr name to the start
      // of the next attr
      name_begin = name_end + 1;
      name_end++;
    }

  free(attrvalbuf);
  free(listbuf);
  
  return 0;
}
#endif

static
int
_create_real_path(const char *dir,
                  const char *file,
                  const char *pattern,
                  char       *real_path,
                  const int   maxlen)
{
  int len;

  len = snprintf(real_path, maxlen, pattern, dir, file);

  return len;
}

int
create_real_path(const char *dir,
                 const char *file,
                 char       *real_path,
                 const int   maxlen)
{
  return _create_real_path(dir, file, "%s/%s", real_path, maxlen);
}

int
create_real_tmppath(const char *dir,
                    const char *file,
                    char       *real_path,
                    const int   maxlen)
{
  return _create_real_path(dir, file, "%s/%s_XXXXXX", real_path, maxlen);
}

char*
find_real_path(const char *fuse_path,
               char       *real_path,
               const int   maxlen)
{
  int i;
  struct stat st;

  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_real_path(mhdd.dirs[i], fuse_path, real_path, maxlen);
      if(lstat(real_path, &st) == 0) 
        return real_path;
    }
  
  return NULL;
}

int
find_real_path_id(const char *fuse_path)
{
  int i;
  struct stat st;
  char real_path[PATH_MAX];

  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_real_path(mhdd.dirs[i], fuse_path, real_path, PATH_MAX);
      if(lstat(real_path, &st) == 0)
        return i;
    }

  return -1;
}

int
create_parent_dirs(int         dir_id,
                   const char *fuse_path)
{
  int rv;
  struct stat st;  
  char real_path[PATH_MAX];
  char parent_path[PATH_MAX];
  char fuse_parent_path[PATH_MAX];
  
  mhdd_debug(MHDD_DEBUG,
             "create_parent_dirs: dir_id=%d, path=%s\n",
             dir_id, fuse_path);

  if(dirname(fuse_path,fuse_parent_path,PATH_MAX) == NULL)
    return (errno = EFAULT,-1);

  if(find_real_path(fuse_parent_path,real_path,PATH_MAX) == NULL)
    return (errno = EFAULT,-1);

  create_real_path(mhdd.dirs[dir_id],fuse_parent_path,parent_path,PATH_MAX);

  // already exists
  if(stat(parent_path, &st) == 0)
    return 0;

  // create parent dirs
  rv = create_parent_dirs(dir_id, parent_path);
  if(rv != 0)
    return rv;

  // get stat from exists dir
  if(stat(real_path, &st) != 0)
    return -1;

  rv = mkdir(parent_path, st.st_mode);
  if(rv != 0)
    {
      mhdd_debug(MHDD_DEBUG,
                 "create_parent_dirs: can not create dir %s: %s\n",
                 parent_path,
                 strerror(errno));
      return -1;
    }
  
  chown(parent_path, st.st_uid, st.st_gid);
  chmod(parent_path, st.st_mode);

#ifndef WITHOUT_XATTR
  copy_xattrs(real_path, parent_path);
#endif

  return 0;
}

static char*
_dirname(const char *start,
         char       *end)
{
  end--;
  start++;

  while(end > start && *end == '/')
    end--;

  while(end > start && *end != '/')
    end--;

  while(end > start && *end == '/')
    end--;

  end[1] = '\0';

  return &end[1];
}  

char*
dirname(char const * const  path,
        char               *parent,
        size_t              maxlen)
{
  char *end;

  end = memccpy(parent,path,'\0',maxlen);
  if(end == NULL)
    return NULL;

  return _dirname(parent, &end[-1]);
}

/* return true if directory is empty */
int
dir_is_empty(const char *path)
{
  DIR *dir;
  struct dirent *de;

  dir = opendir(path);
  if(!dir)
    return -1;

  while((de = readdir(dir)))
    {
      char *d_name = de->d_name;

      if(d_name[0] == '.' &&
         ((d_name[1] == '\0') ||
          (d_name[1] == '.' && d_name[2] == '\0')))
        continue;

      closedir(dir);

      return 0;
    }

  closedir(dir);

  return 1;
}

void
normalize_statvfs(struct statvfs *stat,
                  const unsigned long min_bsize,
                  const unsigned long min_frsize,
                  const unsigned long namemax)
{
  if(stat->f_bsize > min_bsize)
    {
      stat->f_bfree  *=  stat->f_bsize / min_bsize;
      stat->f_bavail *=  stat->f_bsize / min_bsize;
      stat->f_bsize   =  min_bsize;
    }

  if(stat->f_frsize > min_frsize)
    {
      stat->f_blocks *= stat->f_frsize / min_frsize;
      stat->f_frsize  = min_frsize;
    }

  if(stat->f_namemax > namemax)
    stat->f_namemax = namemax;
}

void
merge_statvfs(struct statvfs       * const out,
              const struct statvfs * const in)
{
  out->f_ffree  += in->f_ffree;
  out->f_files  += in->f_files;
  out->f_favail += in->f_favail;
  out->f_bavail += in->f_bavail;
  out->f_bfree  += in->f_bfree;
  out->f_blocks += in->f_blocks;
}

int
myfallocate(int   fd,
            int   mode,
            off_t offset,
            off_t len)
{
  int rv;

#ifdef _GNU_SOURCE
  rv = fallocate(fd,mode,offset,len);
#elif defined _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
  if(mode)
    {
      errno = EOPNOTSUPP;
      rv = -1;
    }
  else
    {
      rv = posix_fallocate(fd,offset,len);
    }
#else
  errno = EOPNOTSUPP;
  rv = -1;
#endif

  return rv;
}

int
has_cap_linux_immutable(const pid_t pid)
{
  int rv;
  cap_t caps;
  cap_flag_value_t cap_flag_value;
  
  caps = cap_get_pid(pid);
  if(caps == NULL)
    return -1;
  
  rv = cap_get_flag(caps,CAP_LINUX_IMMUTABLE,CAP_EFFECTIVE,&cap_flag_value);
  if(rv == -1)
    return -1;
  
  return (cap_flag_value == CAP_SET);
}

int
ioctl_setflags(const int   fd,
               const pid_t pid,
               void       *data)
{
  int rv;
  int flags;

  rv = ioctl(fd,FS_IOC_GETFLAGS,&flags);
  if(rv == -1)
    return -1;

  if(((*(int*)data) ^ flags) & FS_IMMUTABLE_FL)
    {
      rv = has_cap_linux_immutable(pid);
      switch(rv)
        {
        case -1:
          return -1;
        case 0:
          errno = EPERM;
          return -1;
        default:
          break;
        }
    }

  return ioctl(fd,FS_IOC_SETFLAGS,data);
}
               
void
mhdd_asserts()
{
  char parent[PATH_MAX];
  const char const dir[] = "/check/dirname/foo///bar///";
  
  assert(dirname(dir,parent,PATH_MAX) != NULL);
  assert(strcmp("/check/dirname/foo",parent) == 0);

  assert(create_real_path("/a/b/c","d",parent,PATH_MAX) == 8);
  assert(strcmp("/a/b/c/d",parent) == 0);
}
