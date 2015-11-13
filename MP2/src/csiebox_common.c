#include "csiebox_common.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bsd/md5.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <utime.h>



 void sync_file(int conn_fd,int client_id, char* root, char* path) {
  csiebox_protocol_status status;
  fprintf(stderr, "before sync meta for  %s\n", path);
  status = sync_file_meta(conn_fd,client_id, root, path);
  fprintf(stderr, "after sync meta for  %s status is %d\n", path, status);
  if (status == CSIEBOX_PROTOCOL_STATUS_MORE) {
    sync_file_data(conn_fd, client_id, path);
  }
}

 csiebox_protocol_status sync_file_meta(int conn_fd,int client_id, char* root, char* path) {
  char* relative = convert_to_relative_path(root, path);
  if (!relative) {
    fprintf(stderr, "convert relative fail: %s\n", path);
    return CSIEBOX_PROTOCOL_STATUS_FAIL;
  }
  csiebox_protocol_meta meta;
  memset(&meta, 0, sizeof(meta));
  meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  meta.message.header.req.client_id = client_id;
  meta.message.header.req.datalen = sizeof(meta) - sizeof(csiebox_protocol_header);
  meta.message.body.pathlen = strlen(relative);
  lstat(path, &(meta.message.body.stat));
  if ((meta.message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
  } else {
    md5_file(path, meta.message.body.hash);
  }
  fprintf(stderr, "sending meta for: %s\n", path);
  send_message(conn_fd, &meta, sizeof(meta));
  fprintf(stderr, "sending path for: %s\n", path);
  send_message(conn_fd, relative, strlen(relative));
  free(relative);
  
  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status == CSIEBOX_PROTOCOL_STATUS_FAIL) {
    fprintf(stderr, "sync meta fail: %s\n", path);
    return;
  }
  return header.res.status;
}

 void sync_file_data(
  int conn_fd, int client_id, char* path) {
  fprintf(stderr, "file_data: %s\n", path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(path, &stat);
  csiebox_protocol_file file;
  memset(&file, 0, sizeof(file));
  file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
  file.message.header.req.client_id = client_id;
  file.message.header.req.datalen = sizeof(file) - sizeof(csiebox_protocol_header);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    file.message.body.datalen = 0;
    fprintf(stderr, "dir datalen: %zu\n", file.message.body.datalen);
    send_message(conn_fd, &file, sizeof(file));
  } else {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "open fail\n");
      file.message.body.datalen = 0;
      send_message(conn_fd, &file, sizeof(file));
    } else {
      file.message.body.datalen = lseek(fd, 0, SEEK_END);
      fprintf(stderr, "else datalen: %zd\n", file.message.body.datalen);
      send_message(conn_fd, &file, sizeof(file));
      lseek(fd, 0, SEEK_SET);
      char buf[4096];
      memset(buf, 0, 4096);
      size_t readlen;
      while ((readlen = read(fd, buf, 4096)) > 0) {
        send_message(conn_fd, buf, readlen);
      }
      close(fd);
    }
  }

  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
    fprintf(stderr, "sync data fail: %s\n", path);
  }
}

 char* convert_to_relative_path(char* root, const char* path) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  if (path[0] == '/') {
    strcpy(ret, path);
  } else {
    char dir[PATH_MAX];
    memset(dir, 0, PATH_MAX);
    getcwd(dir, PATH_MAX);
    sprintf(ret, "%s/%s", dir, path);
  }
  if (strncmp(root, ret, strlen(root)) != 0) {
    free(ret);
    return NULL;
  }
  size_t rootlen = strlen(root);
  size_t retlen = strlen(ret);
  size_t i;
  for (i = 0; i < retlen; ++i) {
    if (i < rootlen) {
      ret[i] = ret[i + rootlen];
    } else {
      ret[i] = 0;
    }
  }
  return ret;
}


 void sync_file_recieve(char* homedir, int conn_fd, csiebox_protocol_meta* meta) {
  printf("homedir = %s\n", homedir);
  char buf[PATH_MAX], req_path[PATH_MAX];
  memset(buf, 0, PATH_MAX);
  memset(req_path, 0, PATH_MAX);
  recv_message(conn_fd, buf, meta->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);
  free(homedir);
  fprintf(stderr, "req_path: %s\n", req_path);
  struct stat stat;
  memset(&stat, 0, sizeof(struct stat));
  int need_data = 0, change = 0;
  if (lstat(req_path, &stat) < 0) {
    need_data = 1;
    change = 1;
  } else {          
    if(stat.st_mode != meta->message.body.stat.st_mode) { 
      chmod(req_path, meta->message.body.stat.st_mode);
    }       
    if(stat.st_atime != meta->message.body.stat.st_atime ||
       stat.st_mtime != meta->message.body.stat.st_mtime){
      struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
      buf->actime = meta->message.body.stat.st_atime;
      buf->modtime = meta->message.body.stat.st_mtime;
      if(utime(req_path, buf)!=0){
        printf("time fail\n");
      }
    }
    uint8_t hash[MD5_DIGEST_LENGTH];
    memset(hash, 0, MD5_DIGEST_LENGTH);
    if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    } else {
      md5_file(req_path, hash);
    }
    if (memcmp(hash, meta->message.body.hash, MD5_DIGEST_LENGTH) != 0) {
      need_data = 1;
    }

  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  header.res.datalen = 0;
  header.res.client_id = conn_fd;
  if (need_data) {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  }
  send_message(conn_fd, &header, sizeof(header));
  
  if (need_data) {
    csiebox_protocol_file file;
    memset(&file, 0, sizeof(file));
    recv_message(conn_fd, &file, sizeof(file));
    fprintf(stderr, "sync file: %zd\n", file.message.body.datalen);
    if ((meta->message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
      fprintf(stderr, "dir\n");
      mkdir(req_path, DIR_S_FLAG);
    } else {
      fprintf(stderr, "regular file\n");
      int fd = open(req_path, O_CREAT | O_WRONLY | O_TRUNC, REG_S_FLAG);
      size_t total = 0, readlen = 0;;
      char buf[4096];
      memset(buf, 0, 4096);
      while (file.message.body.datalen > total) {
        if (file.message.body.datalen - total < 4096) {
          readlen = file.message.body.datalen - total;
        } else {
          readlen = 4096;
        }
        if (!recv_message(conn_fd, buf, readlen)) {
          fprintf(stderr, "file broken\n");
          break;
        }
        total += readlen;
        if (fd > 0) {
          write(fd, buf, readlen);
        }
      }
      if (fd > 0) {
        close(fd);
      }
    }
    if (change) {
      chmod(req_path, meta->message.body.stat.st_mode);
      struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
      buf->actime = meta->message.body.stat.st_atime;
      buf->modtime = meta->message.body.stat.st_mtime;
      utime(req_path, buf);
    }
    header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    send_message(conn_fd, &header, sizeof(header));
    fprintf(stderr, "file synced\n");
  }
  fprintf(stderr, "sync file ended\n");
}


void md5(const char* str, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]) {
  MD5_CTX ctx;
  MD5Init(&ctx);
  MD5Update(&ctx, (const uint8_t*)str, len);
  MD5Final(digest, &ctx);
}

int md5_file(const char* path, uint8_t digest[MD5_DIGEST_LENGTH]) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  size_t len;
  MD5_CTX ctx;
  MD5Init(&ctx);
  while ((len = read(fd, buf, 4096)) > 0) {
    MD5Update(&ctx, (const uint8_t*)buf, len);
  }
  MD5Final(digest, &ctx);
  close(fd);
  return 1;
}

int recv_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return recv(conn_fd, message, len, MSG_WAITALL) == len;
}

int complete_message_with_header(
  int conn_fd, csiebox_protocol_header* header, void* result) {
  memcpy(result, header->bytes, sizeof(csiebox_protocol_header));
  return recv(conn_fd,
              result + sizeof(csiebox_protocol_header),
              header->req.datalen,
              MSG_WAITALL) == header->req.datalen;
}

int send_message(int conn_fd, void* message, size_t len) {
  if (len == 0) {
    return 0;
  }
  return send(conn_fd, message, len, 0) == len;
}

int get_hash_code(const char* path) {
  struct stat file_stat;
  memset(&file_stat, 0, sizeof(file_stat));
  if (lstat(path, &file_stat) < 0) {
    return 0;
  }
  return (int)file_stat.st_ino;
}
