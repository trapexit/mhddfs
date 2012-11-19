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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <utime.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#ifndef WITHOUT_XATTR
#include <attr/xattr.h>
#endif

#include "tools.h"
#include "debug.h"
#include "parse_options.h"


// get diridx for maximum free space
int
get_free_dir(void)
{
  int i, max, max_perc, max_perc_space = 0;
  struct statvfs stf;
  fsblkcnt_t max_space = 0;

  for (max = i = 0; i < mhdd.dir_count; i++) {

    if(statvfs(mhdd.dirs[i], &stf) != 0)
      continue;
    fsblkcnt_t space  = stf.f_bsize;
    space *= stf.f_bavail;

    if(mhdd.move_limit <= 100) {

      int perc;

      if(mhdd.move_limit != 100) {
        fsblkcnt_t perclimit = stf.f_blocks;

        if(mhdd.move_limit != 99) {
          perclimit *= mhdd.move_limit + 1;
          perclimit /= 100;
        }

        if(stf.f_bavail >= perclimit)
          return i;
      }

      perc = 100 * stf.f_bavail / stf.f_blocks;

      if(perc > max_perc_space) {
        max_perc_space = perc;
        max_perc = i;
      }
    } else {
      if(space >= mhdd.move_limit)
        return i;
    }

    if(space > max_space) {
      max_space = space;
      max = i;
    }
  }


  if(!max_space && !max_perc_space) {
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
static int find_free_space(off_t size)
{
  int i, max;
  struct statvfs stf;
  fsblkcnt_t max_space=0;

  for (max=-1,i=0; i<mhdd.dir_count; i++)
    {
      if(statvfs(mhdd.dirs[i], &stf)!=0) continue;
      fsblkcnt_t space  = stf.f_bsize;
      space *= stf.f_bavail;

      if(space>size+mhdd.move_limit) return i;

      if(space>size && (max<0 || max_space<space))
        {
          max_space=space;
          max=i;
        }
    }
  return max;
}

static int
reopen_files(struct flist * file, const char *new_name)
{
  int i;
  struct flist ** rlist;
  int error = 0;

  mhdd_debug(MHDD_INFO, "reopen_files: %s -> %s\n",
             file->real_name, new_name);
  rlist = flist_items_by_eq_name(file);
  if(!rlist)
    return 0;

  for (i = 0; rlist[i]; i++)
    {
      struct flist * next = rlist[i];
      
      off_t seek = lseek(next->fh, 0, SEEK_CUR);
      int flags = next->flags;
      int fh;
      
      flags &= ~(O_EXCL|O_TRUNC);
      
      // open
      if((fh = open(new_name, flags)) == -1)
        {
          mhdd_debug(MHDD_INFO,
                     "reopen_files: error reopen: %s\n",
                     strerror(errno));
          if(!i)
            {
              error = errno;
              break;
            }
          close(next->fh);
        }
      else
        {
          // seek
          if(seek != lseek(fh, seek, SEEK_SET))
            {
              mhdd_debug(MHDD_INFO,
                         "reopen_files: error seek %s\n",
                         strerror(errno));
              close(fh);
              if(!i)
                {
                  error = errno;
                  break;
                }
            }
          
          // filehandle
          if(dup2(fh, next->fh) != next->fh)
            {
              mhdd_debug(MHDD_INFO,
                         "reopen_files: error dup2 %s\n",
                         strerror(errno));
              close(fh);
              if(!i)
                {
                  error = errno;
                  break;
                }
            }
          // close temporary filehandle
          mhdd_debug(MHDD_MSG,
                     "reopen_files: reopened %s (to %s) old h=%x "
                     "new h=%x seek=%lld\n",
                     next->real_name, new_name, next->fh, fh, seek);
          close(fh);
        }
    }
  
  if(error)
    {
      free(rlist);
      return -error;
    }

  /* change real_name */
  for (i = 0; rlist[i]; i++)
    {
      free(rlist[i]->real_name);
      rlist[i]->real_name = strdup(new_name);
    }

  free(rlist);

  return 0;
}

int
move_file(struct flist * file, off_t wsize)
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

  mhdd_debug(MHDD_MSG, "move_file: %s\n", file->real_name);

  /* TODO: it would be nice to contrive something alter */
  flist_wrlock_locked();
  strcpy(from, file->real_name);
  
  /* We need to check if already moved */
  if(statvfs(from, &svf) != 0)
    return -errno;
  space = svf.f_bsize;
  space *= svf.f_bavail;

  /* get file size */
  if(fstat(file->fh, &st) != 0)
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
      mhdd_debug(MHDD_MSG, "move_file: cannot move "
                 "files with >1 hardlinks\n");
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

  create_parent_dirs(dir_id, file->name);

  create_path(mhdd.dirs[dir_id], file->name, to);
  create_tmppath(mhdd.dirs[dir_id], file->name, to_tmp);

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
  
  ret = reopen_files(file, to);
  if(ret == 0)
    unlink(from);      
  else
    unlink(to);

  mhdd_debug(MHDD_MSG, "move_file: %s -> %s: done, code=%d\n",
             from, to, ret);

  return ret;
}

#ifndef WITHOUT_XATTR
int
copy_xattrs(const char *from, const char *to)
{
  int listsize=0, attrvalsize=0;
  char *listbuf=NULL, *attrvalbuf=NULL,
    *name_begin=NULL, *name_end=NULL;

  // if not xattrs on source, then do nothing
  if((listsize=listxattr(from, NULL, 0)) == 0)
    return 0;

  // get all extended attributes
  listbuf=(char *)calloc(sizeof(char), listsize);
  if(listxattr(from, listbuf, listsize) == -1)
    {
      mhdd_debug(MHDD_MSG,
                 "listxattr: error listing xattrs on %s : %s\n",
                 from, strerror(errno));
      return -1;
    }

  // loop through each xattr
  for(name_begin=listbuf, name_end=listbuf+1;
      name_end < (listbuf + listsize); name_end++)
    {
      // skip the loop if we're not at the end of an attribute name
      if(*name_end != '\0')
        continue;

      // get the size of the extended attribute
      attrvalsize = getxattr(from, name_begin, NULL, 0);
      if(attrvalsize < 0)
        {
          mhdd_debug(MHDD_MSG,
                     "getxattr: error getting xattr size on %s name %s : %s\n",
                     from, name_begin, strerror(errno));
          return -1;
        }

      // get the value of the extended attribute
      attrvalbuf=(char *)calloc(sizeof(char), attrvalsize);
      if(getxattr(from, name_begin, attrvalbuf, attrvalsize) < 0)
        {
          mhdd_debug(MHDD_MSG,
                     "getxattr: error getting xattr value on %s name %s : %s\n",
                     from, name_begin, strerror(errno));
          return -1;
        }

      // set the value of the extended attribute on dest file
      if(setxattr(to, name_begin, attrvalbuf, attrvalsize, 0) < 0)
        {
          mhdd_debug(MHDD_MSG,
                     "setxattr: error setting xattr value on %s name %s : %s\n",
                     from, name_begin, strerror(errno));
          return -1;
        }

      free(attrvalbuf);

      // point the pointer to the start of the attr name to the start
      // of the next attr
      name_begin=name_end+1;
      name_end++;
    }

  free(listbuf);
  return 0;
}
#endif

void
_create_path(const char *dir, const char *file, const char *pattern, char path[PATH_MAX])
{
  int len;

  while(*file == '/')
    file++;

  len = snprintf(path, PATH_MAX, "%s/%s", dir, file);

  while(path[len] == '/')
    path[len--] = '\0';
}

void
create_path(const char *dir, const char *file, char path[PATH_MAX])
{
  _create_path(dir, file, "%s/%s", path);
}

void
create_tmppath(const char *dir, const char *file, char path[PATH_MAX])
{
  _create_path(dir, file, "%s/%s_XXXXXX", path);
}

char *
find_fullpath(const char *file, char path[PATH_MAX])
{
  int i;
  struct stat st;

  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_path(mhdd.dirs[i], file, path);
      if(lstat(path, &st) == 0) 
        return path;
    }
  
  return NULL;
}

int
find_fullpath_id(const char *file)
{
  int i;
  struct stat st;
  char path[PATH_MAX];

  for(i = 0; i < mhdd.dir_count; i++)
    {
      create_path(mhdd.dirs[i], file, path);
      if(lstat(path, &st) == 0)
        return i;
    }

  return -1;
}

int
create_parent_dirs(int dir_id, const char *path)
{
  char *parent;
  struct stat st;  
  char fullpath[PATH_MAX];
  char parent_path[PATH_MAX];  
  
  mhdd_debug(MHDD_DEBUG,
             "create_parent_dirs: dir_id=%d, path=%s\n", dir_id, path);

  parent = get_parent_path(path);
  if(!parent)
    return 0;

  if(find_fullpath(parent,fullpath) == NULL)
    {
      free(parent);
      errno=EFAULT;
      return -errno;
    }

  create_path(mhdd.dirs[dir_id], parent, parent_path);

  // already exists
  if(stat(parent_path, &st)==0)
    {
      free(parent);
      return 0;
    }

  // create parent dirs
  int res = create_parent_dirs(dir_id, parent);

  if(res != 0)
    {
      free(parent);
      return res;
    }

  // get stat from exists dir
  if(stat(fullpath, &st) != 0)
    {
      free(parent);
      return -errno;
    }

  res = mkdir(parent_path, st.st_mode);
  if(res == 0)
    {
      chown(parent_path, st.st_uid, st.st_gid);
      chmod(parent_path, st.st_mode);
    }
  else
    {
      res = -errno;
      mhdd_debug(MHDD_DEBUG,
                 "create_parent_dirs: can not create dir %s: %s\n",
                 parent_path,
                 strerror(errno));
    }

#ifndef WITHOUT_XATTR
  // copy extended attributes of parent dir
  if(copy_xattrs(fullpath, parent_path) == -1)
    mhdd_debug(MHDD_MSG,
               "copy_xattrs: error copying xattrs from %s to %s\n",
               fullpath, parent_path);
#endif

  free(parent);

  return res;
}

char *
get_parent_path(const char * path)
{
  int len;
  char *dir;

  len = strlen(path);
  dir = strdup(path);
  
  if(len && dir[len-1] == '/')
    dir[--len] = 0;

  while(len && dir[len-1] != '/')
    dir[--len] = 0;

  if(len > 1 && dir[len-1] == '/')
    dir[--len] = 0;

  if(len)
    return dir;

  free(dir);

  return NULL;
}

/* return true if directory is empty */
int
dir_is_empty(const char *path)
{
  DIR * dir = opendir(path);
  struct dirent *de;

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
