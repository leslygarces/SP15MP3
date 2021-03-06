#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm);
static void send_end_sync_to_client(int conn_fd) ;
static void sync_all_to_client(char* cwd, char* homedir, int conn_fd) ;


static void sync_all_to_client(char* cwd, char* homedir, int conn_fd) {
  chdir(cwd);
  DIR* dir;
  struct dirent* file;
  struct stat file_stat;
  dir = opendir(".");
  while ((file = readdir(dir)) != NULL) {
    if (strcmp(file->d_name, ".") == 0 ||
        strcmp(file->d_name, "..") == 0) {
    continue;
    }
    lstat(file->d_name, &file_stat); 
    sync_file(conn_fd,conn_fd,homedir, file->d_name);
    if ((file_stat.st_mode & S_IFMT) == S_IFDIR) {
      if (chdir(file->d_name) != 0) {
        fprintf(stderr, "bad dir %s\n", file->d_name);
        continue;
      }
      sync_all_to_client(file->d_name, homedir, conn_fd);
      chdir(cwd);
    }
  }
  closedir(dir);
  free(cwd);
  send_end_sync_to_client(conn_fd);
  return;
}

void csiebox_server_init(csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file] [-d]\n", argv[0]);
    free(tmp);
    return;
  }

  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->sock = fd;
  *server = tmp;
}

int csiebox_server_run(csiebox_server* server) { 
  int conn_fd, conn_len;
  struct sockaddr_in clientname;
  size_t size;  
  fd_set active_fd_set, read_fd_set;
  int i;
  FD_ZERO (&active_fd_set);
  FD_SET (server->sock, &active_fd_set);

  while (1) {

      /* Block until input arrives on one or more active sockets. */
      read_fd_set = active_fd_set;
      fprintf(stderr, "Block until input arrives on one or more active sockets...\n");      
      if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0)
        {
          perror ("select");
          exit (EXIT_FAILURE);
        }

      fprintf(stderr, "unblocked....\n");      

      /* Service all the sockets with input pending. */
      for (i = 0; i < FD_SETSIZE; ++i) {
        if (FD_ISSET (i, &read_fd_set))
          {
            if (i == server->sock)
              {
                /* Connection request on original socket. */
                fprintf(stderr, "Connection request on original socket...\n");
                int new;
                size = sizeof (clientname);
                new = accept (server->sock,
                              (struct sockaddr *) &clientname,
                              &size);
                if (new < 0)
                  {
                    perror ("accept");
                    exit (EXIT_FAILURE);
                  }
                fprintf (stderr,
                         "Server: connect from host %s, port %hd.\n",
                         inet_ntoa (clientname.sin_addr),
                         ntohs (clientname.sin_port));
                FD_SET (new, &active_fd_set);
              }
            else
              {
                fprintf(stderr, "before handle_request...\n");              
                /* Data arriving on an already-connected socket. */
                if (!handle_request(server, i)) {
                    //close (i);
                    fprintf(stderr, "*******clearing client...\n");
                    FD_CLR (i, &active_fd_set);
                }
                fprintf(stderr, "after handle_request new ...\n");              

                  
              }
          }
    }
  }
  return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  //close(tmp->listen_fd);
  free(tmp->client);
  free(tmp);
}

static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}

static void send_end_sync_to_client(int conn_fd) {
  csiebox_protocol_header req;
  memset(&req, 0, sizeof(req));
  req.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
  req.req.datalen = 0;
  send_message(conn_fd, &req, sizeof(req));
}

static int handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(conn_fd, &header, sizeof(header))) {
  	if (header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ) {
  	  switch (header.req.op) {
        case CSIEBOX_PROTOCOL_OP_LOGIN:
    	    fprintf(stderr, "login\n");
    	    csiebox_protocol_login req;
    	    if (complete_message_with_header(conn_fd, &header, &req)) {
    	      login(server, conn_fd, &req);
            fprintf(stderr, "before sync all\n");
            csiebox_client_info* info = server->client[conn_fd];
            char* homedir = get_user_homedir(server, info);
            sync_all_to_client(homedir,homedir, conn_fd);
            fprintf(stderr, "after sync all\n");
    	    }
    	    break;
    	  case CSIEBOX_PROTOCOL_OP_SYNC_META:
    	    fprintf(stderr, "sync meta\n");
    	    csiebox_protocol_meta meta;
    	    if (complete_message_with_header(conn_fd, &header, &meta)) {
            csiebox_client_info* info = server->client[conn_fd];
            char* homedir = get_user_homedir(server, info);
    	      sync_file_recieve(homedir, conn_fd, &meta);
    	    }
          fprintf(stderr, "end sync meta\n");
    	    break;
    	  case CSIEBOX_PROTOCOL_OP_SYNC_END:
    	    fprintf(stderr, "sync end\n");
    	    break;
    	  case CSIEBOX_PROTOCOL_OP_RM:
    	    fprintf(stderr, "rm\n");
    	    csiebox_protocol_rm rm;
    	    if (complete_message_with_header(conn_fd, &header, &rm)) {
    	      rm_file(server, conn_fd, &rm);
    	    }
    	    break;
    	  default:
    	    fprintf(stderr, "unknow op %x\n", header.req.op);
    	    break;
  	  }    
    }
  }else {
    return 0;
  }
  return 1;
}
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    fprintf(stderr, "could not open accounts file\n");
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "ill form in account file, line %d\n", line);
      continue;
    }
    fprintf(stderr, "checking user %s\n",u);
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "ill form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}

static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info = (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account %s\n",login->message.body.user);
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm) {
  csiebox_client_info* info = server->client[conn_fd];
  char* homedir = get_user_homedir(server, info);
  char req_path[PATH_MAX], buf[PATH_MAX];
  memset(req_path, 0, PATH_MAX);
  memset(buf, 0, PATH_MAX);
  recv_message(conn_fd, buf, rm->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);
  free(homedir);
  fprintf(stderr, "rm (%zd, %s)\n", strlen(req_path), req_path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(req_path, &stat);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    rmdir(req_path);
  } else {
    unlink(req_path);
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_RM;
  header.res.datalen = 0;
  header.res.client_id = conn_fd;
  header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  send_message(conn_fd, &header, sizeof(header));
}
