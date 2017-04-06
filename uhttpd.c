/*
 * uhttpd - Tiny single-threaded httpd - Main component
 *
 *   Copyright (C) 2010 Jo-Philipp Wich <xm@subsignal.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "uhttpd.h"
#include "uhttpd-file.h"
#include "uhttpd-utils.h"

/**
 * uhttpd服务器接受的请求会根据请求头分成三类，静态文件请求，
 * cgi请求（处理表单信息）和lua请求（功能强大实现多功能的处理和调用）
 *
 * HAVE_CGI HAVE_LUA HAVE_UBUS是在CMake中定义的（CMakeLists.txt）
 * OPTION(CGI_SUPPORT "CGI support" ON)
 * 此时表示，如果用户没有定义过address,那么address的默认值就是ON
 *
 * 如何设置CMake中的option变量值？
 *
 * CMakeLists.txt：
 * option(MyOption "MyOption" OFF)
 *
 * Command line：
 * cmake -DMyOption=ON MyProjectFolder
 */
#ifdef HAVE_CGI
#include "uhttpd-cgi.h"
#endif

#ifdef HAVE_LUA
#include "uhttpd-lua.h"
#endif

#ifdef HAVE_TLS
#include "uhttpd-tls.h"
#endif

const char *http_methods[] = {
    "GET", "POST", "HEAD",
};
const char *http_versions[] = {
    "HTTP/0.9", "HTTP/1.0", "HTTP/1.1",
};

static int run = 1;

/**
 * 静态函数会被自动分配在一个一直使用的存储区，
 * 直到退出应用程序实例，避免了调用函数时压栈出栈，速度快很多。
 */
static void uh_sigterm(int sig) { run = 0; }

/**
 * 使用配置文件进行配置
 */
static void uh_config_parse(struct config *conf) {
  FILE *c;
  char line[512];
  char *col1 = NULL;
  char *col2 = NULL;
  char *eol = NULL;

  const char *path = conf->file ? conf->file : "/etc/httpd.conf";

  if ((c = fopen(path, "r")) != NULL) {
    memset(line, 0, sizeof(line));

    while (fgets(line, sizeof(line) - 1, c)) {
      if ((line[0] == '/') && (strchr(line, ':') != NULL)) {
        //检查路径权限设置格式
        if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
            !(col2 = strchr(col1, ':')) || (*col2++ = 0) ||
            !(eol = strchr(col2, '\n')) || (*eol++ = 0)) {
          continue;
        }

        //新增路径权限设置
        if (!uh_auth_add(line, col1, col2)) {
          fprintf(stderr, "Notice: No password set for user %s, ignoring "
                          "authentication on %s\n",
                  col1, line);
        }
      } else if (!strncmp(line, "I:", 2)) {
        if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
            !(eol = strchr(col1, '\n')) || (*eol++ = 0)) {
          continue;
        }

        //新增默认文档
        if (!uh_index_add(strdup(col1))) {
          fprintf(stderr, "Unable to add index filename %s: "
                          "Out of memory\n",
                  col1);
        }
      } else if (!strncmp(line, "E404:", 5)) {
        if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
            !(eol = strchr(col1, '\n')) || (*eol++ = 0)) {
          continue;
        }

        // 404处理设置
        conf->error_handler = strdup(col1);
      }
#ifdef HAVE_CGI
      else if ((line[0] == '*') && (strchr(line, ':') != NULL)) {
        if (!(col1 = strchr(line, '*')) || (*col1++ = 0) ||
            !(col2 = strchr(col1, ':')) || (*col2++ = 0) ||
            !(eol = strchr(col2, '\n')) || (*eol++ = 0)) {
          continue;
        }

        // 新增CGI解析器
        if (!uh_interpreter_add(col1, col2)) {
          fprintf(stderr, "Unable to add interpreter %s for extension %s: "
                          "Out of memory\n",
                  col2, col1);
        }
      }
#endif
    }

    fclose(c);
  }
}

static void uh_listener_cb(struct uloop_fd *u, unsigned int events);

/*
  绑定、创建socket
*/
static int uh_socket_bind(const char *host, const char *port,
                          struct addrinfo *hints, int do_tls,
                          struct config *conf) {
  int sock = -1;
  int yes = 1;
  int status;
  int bound = 0;

#ifdef linux
  int tcp_ka_idl, tcp_ka_int, tcp_ka_cnt;
#endif

  struct listener *l = NULL;
  struct addrinfo *addrs = NULL, *p = NULL;

  if ((status = getaddrinfo(host, port, hints, &addrs)) != 0) {
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(status));
  }

  /*
    如果HOST中找到多个IP地址，则每一个IP地址建立一个SOCKET
  */
  for (p = addrs; p; p = p->ai_next) {
    /* get the socket */
    if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket()");
      goto error;
    }

    /*
      定义函数：int setsockopt(int s, int level, int optname, const void
      *optval, ,socklen_toptlen);

      函数说明：setsockopt()用来设置参数s 所指定的socket 状态. 参数level
      代表欲设置的网络层, 一般设成SOL_SOCKET 以存取socket 层. 参数optname
      代表欲设置的选项, 有下列几种数值:
        SO_DEBUG 打开或关闭排错模式
        SO_REUSEADDR 允许在bind ()过程中本地地址可重复使用
        SO_TYPE 返回socket 形态.
        SO_ERROR 返回socket 已发生的错误原因
        SO_DONTROUTE 送出的数据包不要利用路由设备来传输.
        SO_BROADCAST 使用广播方式传送
        SO_SNDBUF 设置送出的暂存区大小
        SO_RCVBUF 设置接收的暂存区大小
        SO_KEEPALIVE 定期确定连线是否已终止.
        SO_OOBINLINE 当接收到OOB 数据时会马上送至标准输入设备
        SO_LINGER 确保数据安全且可靠的传送出去.

      参数 optval 代表欲设置的值, 参数optlen 则为optval 的长度.

      返回值：成功则返回0, 若有错误则返回-1, 错误原因存于errno.

      附加说明：
      1、EBADF 参数s 并非合法的socket 处理代码
      2、ENOTSOCK 参数s 为一文件描述词, 非socket
      3、ENOPROTOOPT 参数optname 指定的选项不正确.
      4、EFAULT 参数optval 指针指向无法存取的内存空间.
    */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
      perror("setsockopt()");
      goto error;
    }

    /*
      TCP/IP协议自身提供的KeepAlive机制
      不建议使用，会有各种原因让tcp keep-alive失效
      所以应用要自己有心跳包
     */
    if (conf->tcp_keepalive > 0) {
#ifdef linux
      tcp_ka_idl = 1;
      tcp_ka_cnt = 3;
      tcp_ka_int = conf->tcp_keepalive;
#endif

      if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes))
#ifdef linux
          || setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, &tcp_ka_idl,
                        sizeof(tcp_ka_idl)) ||
          setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &tcp_ka_int,
                     sizeof(tcp_ka_int)) ||
          setsockopt(sock, SOL_TCP, TCP_KEEPCNT, &tcp_ka_cnt,
                     sizeof(tcp_ka_cnt))
#endif
              ) {
        fprintf(stderr, "Notice: Unable to enable TCP keep-alive: %s\n",
                strerror(errno));
      }
    }

    /* required to get parallel v4 + v6 working */
    if (p->ai_family == AF_INET6) {
      if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) ==
          -1) {
        perror("setsockopt()");
        goto error;
      }
    }

    /* bind */
    if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
      perror("bind()");
      goto error;
    }

    /* listen */
    if (listen(sock, UH_LIMIT_CLIENTS) == -1) {
      perror("listen()");
      goto error;
    }

    /* 把socket加到了一个全局的listener链表中 */
    if (!(l = uh_listener_add(sock, conf))) {
      fprintf(stderr, "uh_listener_add(): Failed to allocate memory\n");
      goto error;
    }

#ifdef HAVE_TLS
    /* init TLS */
    l->tls = do_tls ? conf->tls : NULL;
#endif

    /* add socket to uloop */
    fd_cloexec(sock);
    // fd注册到IO模型中，第二个参数为绑定的事件
    uh_ufd_add(&l->fd, uh_listener_cb, ULOOP_READ);

    bound++;
    continue;

  error:
    if (sock > 0)
      close(sock);
  }

  freeaddrinfo(addrs);

  return bound;
}

/**
 * header请求解析
 * @param cl 客户端结构体
 * @param buffer 请求报文
 * @param buflen 请求报文长度
 */
static struct http_request *uh_http_header_parse(struct client *cl,
                                                 char *buffer, int buflen) {
  //请求方法
  char *method = buffer;
  //请求路径
  char *path = NULL;
  //请求HTTP版本
  char *version = NULL;

  //起始行指针
  char *headers = NULL;
  char *hdrname = NULL;
  char *hdrdata = NULL;

  int i;
  int hdrcount = 0;

  struct http_request *req = &cl->request;

  /* terminate initial header line */
  if ((headers = strfind(buffer, buflen, "\r\n", 2)) != NULL) {
    //请求报文结尾添加结束符
    buffer[buflen - 1] = 0;

    //\r\n替换成结束符
    *headers++ = 0;
    *headers++ = 0;

    /* 获取请求地址 */
    if ((path = strchr(buffer, ' ')) != NULL)
      *path++ = 0;

    /* 获取请求HTTP版本 */
    if ((path != NULL) && ((version = strchr(path, ' ')) != NULL))
      *version++ = 0;

    /* 检查HTTP方法 */
    if (method && !strcmp(method, "GET"))
      req->method = UH_HTTP_MSG_GET;
    else if (method && !strcmp(method, "POST"))
      req->method = UH_HTTP_MSG_POST;
    else if (method && !strcmp(method, "HEAD"))
      req->method = UH_HTTP_MSG_HEAD;
    else {
      /* invalid method */
      uh_http_response(cl, 405, "Method Not Allowed");
      return NULL;
    }

    /* 检查是否有请求地址 */
    if (!path || !strlen(path)) {
      /* malformed request */
      uh_http_response(cl, 400, "Bad Request");
      return NULL;
    } else {
      req->url = path;
    }

    /* 检查HTTP版本 */
    if (version && !strcmp(version, "HTTP/0.9"))
      req->version = UH_HTTP_VER_0_9;
    else if (version && !strcmp(version, "HTTP/1.0"))
      req->version = UH_HTTP_VER_1_0;
    else if (version && !strcmp(version, "HTTP/1.1"))
      req->version = UH_HTTP_VER_1_1;
    else {
      /* unsupported version */
      uh_http_response(cl, 400, "Bad Request");
      return NULL;
    }

    D("SRV: %s %s %s\n", http_methods[req->method], req->url,
      http_versions[req->version]);

    /* process header fields */
    for (i = (int)(headers - buffer); i < buflen; i++) {
      /**
       * found eol and have name + value, push out header tuple
       * 找到了首部键值对，存到http_request的headers中
       */
      if (hdrname && hdrdata && (buffer[i] == '\r' || buffer[i] == '\n')) {
        buffer[i] = 0;

        /* store */
        if ((hdrcount + 1) < array_size(req->headers)) {
          D("SRV: HTTP: %s: %s\n", hdrname, hdrdata);

          req->headers[hdrcount++] = hdrname;
          req->headers[hdrcount++] = hdrdata;

          hdrname = hdrdata = NULL;
        }
        /* too large */
        else {
          D("SRV: HTTP: header too big (too many headers)\n");
          uh_http_response(cl, 413, "Request Entity Too Large");
          return NULL;
        }
      }
      /**
       * have name but no value and found a colon, start of value
       * 获取键名对应的键值
       */
      else if (hdrname && !hdrdata && ((i + 1) < buflen) &&
               (buffer[i] == ':')) {
        buffer[i] = 0;
        hdrdata = &buffer[i + 1];
        //如果中间有空格，定位到空格后面
        while ((hdrdata + 1) < (buffer + buflen) && *hdrdata == ' ')
          hdrdata++;
      }
      /**
       * have no name and found [A-Za-z], start of name
       * 获取请求首部键名
       */
      else if (!hdrname && isalpha(buffer[i])) {
        hdrname = &buffer[i];
      }
    }

    /* 请求报文验证没问题 */
    req->redirect_status = 200;
    return req;
  }

  /* Malformed request */
  uh_http_response(cl, 400, "Bad Request");
  return NULL;
}

static bool uh_http_header_check_method(const char *buf, ssize_t rlen) {
  int i;

  for (i = 0; i < sizeof(http_methods) / sizeof(http_methods[0]); i++)
    if (!strncmp(buf, http_methods[i], min(rlen, strlen(http_methods[i]))))
      return true;

  return false;
}

/**
 * 解析请求报文
 */
static struct http_request *uh_http_header_recv(struct client *cl) {
  char *bufptr = cl->httpbuf.buf;
  char *idxptr = NULL;

  ssize_t blen = sizeof(cl->httpbuf.buf) - 1;
  ssize_t rlen = 0;

  memset(bufptr, 0, sizeof(cl->httpbuf.buf));

  while (blen > 0) {
    /* 如果没有读取到数据则跳到结束 */
    ensure_out(rlen = uh_tcp_recv(cl, bufptr, blen));
    D("SRV: Client(%d) peek(%d) = %d\n", cl->fd.fd, blen, rlen);

    if (rlen <= 0) {
      D("SRV: Client(%d) dead [%s]\n", cl->fd.fd, strerror(errno));
      return NULL;
    }

    /**
     * 如果是第一次read，则检查头部信息
     */
    if ((bufptr == cl->httpbuf.buf) &&
        !uh_http_header_check_method(bufptr, rlen)) {
      D("SRV: Client(%d) no valid HTTP method, abort\n", cl->fd.fd);
      uh_http_response(cl, 400, "Bad Request");
      return NULL;
    }

    /**
     * 计算是否已经超过buffer的大小
     */
    blen -= rlen;

    /**
     * bufptr指针移到所读到数据的最后
     * 以便读入的新数据追加到cl->httpbuf.buf数组中
     */
    bufptr += rlen;

    /**
     * strfind返回寻找字符串的第一个指针
     * 当找到请求报文结尾（HTTP请求报文最后为 两个回车符换行符）
     */
    if ((idxptr = strfind(cl->httpbuf.buf, sizeof(cl->httpbuf.buf), "\r\n\r\n",
                          4))) {
      /* 请求报文已经全部读取 */

      //指针移动到请求首部最后（请求正文初始位置）
      cl->httpbuf.ptr = idxptr + 4;

      /**
       * 指针相减的陷阱两个指针相减，结果并不是两个指针数值上的差，而是把这个差除以指针指向类型的大小的结果。
       * 如果两个指针向同一个数组，它们就可以相减，其为结果为两个指针之间的元素数目
       *
       * 获取请求正文（例如：POST数据）的长度
       */
      cl->httpbuf.len = bufptr - cl->httpbuf.ptr;

      return uh_http_header_parse(cl, cl->httpbuf.buf,
                                  (cl->httpbuf.ptr - cl->httpbuf.buf));
    }
  }

  /* request entity too large */
  D("SRV: HTTP: header too big (buffer exceeded)\n");
  uh_http_response(cl, 413, "Request Entity Too Large");

out:
  return NULL;
}

#if defined(HAVE_LUA) || defined(HAVE_CGI)
/**
 * 检查是否匹配某个类型的路径
 */
static int uh_path_match(const char *prefix, const char *url) {
  if ((strstr(url, prefix) == url) &&
      ((prefix[strlen(prefix) - 1] == '/') || (strlen(url) == strlen(prefix)) ||
       (url[strlen(prefix)] == '/'))) {
    return 1;
  }

  return 0;
}
#endif

/**
 * 1、在分发过程（不包括lua请求）当中，会根据path的前缀来判断是CGI请求还是静态文件请求，默认的CGI前缀是/cgi-bin
 * （CGI请求进入uh_cgi_request，文件请求进入uh_file_request，lua请求则会进入lua_request）
 * 2、初始化cl中执行动态脚本后的设置以及处理函数
 */
static bool uh_dispatch_request(struct client *cl, struct http_request *req) {
  struct path_info *pin;
#ifdef HAVE_CGI
  struct interpreter *ipr = NULL;
#endif
  struct config *conf = cl->server->conf;

#ifdef HAVE_LUA
  /* Lua request? */
  if (conf->lua_state && uh_path_match(conf->lua_prefix, req->url)) {
    return conf->lua_request(cl, conf->lua_state);
  } else
#endif

#ifdef HAVE_UBUS
      /* ubus request? */
      if (conf->ubus_state && uh_path_match(conf->ubus_prefix, req->url)) {
    return conf->ubus_request(cl, conf->ubus_state);
  } else
#endif

      /* dispatch request */
      if ((pin = uh_path_lookup(cl, req->url)) != NULL) {
    /* 检查请求路径权限 */
    if (!pin->redirected && uh_auth_check(cl, req, pin)) {
#ifdef HAVE_CGI
      /* 是否在CGI前缀目录下的文件或者文件后缀是否有关联的解析器 */
      if (uh_path_match(conf->cgi_prefix, pin->name) ||
          (ipr = uh_interpreter_lookup(pin->phys)) != NULL) {
        return uh_cgi_request(cl, pin, ipr);
      }
#endif
      return uh_file_request(cl, pin);
    }
  }

  /* 404 - pass 1 */
  else {
    /* 尝试触发404错误处理 */
    if ((pin = uh_path_lookup(cl, conf->error_handler)) != NULL) {
      /* auth ok? */
      if (uh_auth_check(cl, req, pin)) {
        req->redirect_status = 404;
#ifdef HAVE_CGI
        if (uh_path_match(conf->cgi_prefix, pin->name) ||
            (ipr = uh_interpreter_lookup(pin->phys)) != NULL) {
          return uh_cgi_request(cl, pin, ipr);
        }
#endif
        return uh_file_request(cl, pin);
      }
    }

    /* 404 - pass 2 */
    else {
      uh_http_sendhf(cl, 404, "Not Found", "No such file or directory");
    }
  }

  return false;
}

static void uh_socket_cb(struct uloop_fd *u, unsigned int events);

static void uh_listener_cb(struct uloop_fd *u, unsigned int events) {
  int new_fd;
  struct listener *serv;
  struct client *cl;
  struct config *conf;

  struct sockaddr_in6 sa;
  socklen_t sl = sizeof(sa);

  serv = container_of(u, struct listener, fd);
  conf = serv->conf;

  /* defer client if maximum number of requests is exceeded */
  if (serv->n_clients >= conf->max_requests)
    return;

  /* 处理新连接 */
  if ((new_fd = accept(u->fd, (struct sockaddr *)&sa, &sl)) != -1) {
    D("SRV: Server(%d) accept => Client(%d)\n", u->fd, new_fd);

    /* 将新连接添加到全局client链表中 */
    if ((cl = uh_client_add(new_fd, serv, &sa)) != NULL) {
      /* 将socket绑定到IO模型的可读监听中 */
      uh_ufd_add(&cl->fd, uh_socket_cb, ULOOP_READ);
      fd_cloexec(cl->fd.fd);

#ifdef HAVE_TLS
      /* setup client tls context */
      if (conf->tls) {
        if (conf->tls_accept(cl) < 1) {
          D("SRV: Client(%d) SSL handshake failed, drop\n", new_fd);

          /* remove from global client list */
          uh_http_response(cl, 400, "Bad Request");
          uh_client_remove(cl);
          return;
        }
      }
#endif
    }

    /* insufficient resources */
    else {
      fprintf(stderr, "uh_client_add(): Cannot allocate memory\n");
      close(new_fd);
    }
  }
}

static void uh_client_cb(struct client *cl, unsigned int events);

static void uh_rpipe_cb(struct uloop_fd *u, unsigned int events) {
  struct client *cl = container_of(u, struct client, rpipe);

  D("SRV: Client(%d) rpipe readable\n", cl->fd.fd);

  uh_client_cb(cl, ULOOP_WRITE);
}

static void uh_socket_cb(struct uloop_fd *u, unsigned int events) {
  struct client *cl = container_of(u, struct client, fd);

  D("SRV: Client(%d) socket readable\n", cl->fd.fd);

  uh_client_cb(cl, ULOOP_READ);
}

#if defined(HAVE_CGI) || defined(HAVE_LUA) || defined(HAVE_UBUS)
/**
 * 子线程结束回调函数
 */
static void uh_child_cb(struct uloop_process *p, int rv) {
  struct client *cl = container_of(p, struct client, proc);

  D("SRV: Client(%d) child(%d) dead\n", cl->fd.fd, cl->proc.pid);

  uh_client_cb(cl, ULOOP_READ | ULOOP_WRITE);
}

/**
 * 强制终止进程
 */
static void uh_kill9_cb(struct uloop_timeout *t) {
  struct client *cl = container_of(t, struct client, timeout);

  if (!kill(cl->proc.pid, 0)) {
    D("SRV: Client(%d) child(%d) kill(SIGKILL)...\n", cl->fd.fd, cl->proc.pid);

    /**
     * SIGKILL信号，进程是不能忽略的。 这是一个
     * '“我不管您在做什么,立刻停止”'的信号。 假如您发送SIGKILL信号给进程，
     * FreeBSD就将进程停止在那里。
     */
    kill(cl->proc.pid, SIGKILL);
  }
}

/**
 * 进程超时回调
 */
static void uh_timeout_cb(struct uloop_timeout *t) {
  struct client *cl = container_of(t, struct client, timeout);

  D("SRV: Client(%d) child(%d) timed out\n", cl->fd.fd, cl->proc.pid);

  /**
   * 定义函数：int kill(pid_t pid, int sig);
   * 函数说明：kill()可以用来送参数sig 指定的信号给参数pid 指定的进程。参数pid
   * 有几种情况：
   * 1、pid>0 将信号传给进程识别码为pid 的进程.
   * 2、pid=0 将信号传给和目前进程相同进程组的所有进程
   * 3、pid=-1 将信号广播传送给系统内所有的进程
   * 4、pid<0 将信号传给进程组识别码为pid 绝对值的所有进程参数 sig
   * 代表的信号编号可参考附录D
   * 返回值：执行成功则返回0, 如果有错误则返回-1.
   */
  if (!kill(cl->proc.pid, 0)) {
    D("SRV: Client(%d) child(%d) kill(SIGTERM)...\n", cl->fd.fd, cl->proc.pid);

    /**
     * SIGTERM (软中断) 使用不带参数的kill命令时终止进程
     * SIGTERM比较友好，进程能捕捉这个信号，
     * 根据您的需要来关闭程序。在关闭程序之前，您可以结束打开的记录文件和完成正在做的任务。
     * 在某些情况下， 假如进程正在进行作业而且不能中断，那么进程可以忽略这个
     * SIGTERM信号。
     */
    kill(cl->proc.pid, SIGTERM);

    /* SIGTERM处理超时则直接调用SIGKILL强制终止进程 */
    cl->timeout.cb = uh_kill9_cb;
    uloop_timeout_set(&cl->timeout, 1000);
  }
}
#endif

/**
 * 客户端请求处理函数
 */
static void uh_client_cb(struct client *cl, unsigned int events) {
  int i;
  struct config *conf;
  struct http_request *req;

  conf = cl->server->conf;

  D("SRV: Client(%d) enter callback\n", cl->fd.fd);

  //如果还没分发请求
  if (!cl->dispatched) {
    /* 还没有请求报文而且又是一个读事件 */
    if (!(events & ULOOP_READ)) {
      D("SRV: Client(%d) ignoring write event before headers\n", cl->fd.fd);
      return;
    }

    /* 尝试获取和解析请求报文 */
    if (!(req = uh_http_header_recv(cl))) {
      D("SRV: Client(%d) failed to receive header\n", cl->fd.fd);
      uh_client_shutdown(cl);
      return;
    }

    /**
     * The Expect request-header field is used to indicate that
     * particular server behaviors are required by the client.
     *
     * 在使用curl做POST的时候, 当要POST的数据大于1024字节的时候,
     * curl并不会直接就发起POST请求, 而是会分为俩步,
     * 1. 发送一个请求, 包含一个Expect:100-continue, 询问Server使用愿意接受数据
     * 2. 接收到Server返回的100 Continue应答以后, 才把数据POST给Server
     *
     * 解决方法
     * 手动设置Expect的值为false或者空，即不进行握手，而直接Post数据。
     */
    foreach_header(i, req->headers) {
      //处理Expect:100-continue请求首部
      if (strcasecmp(req->headers[i], "Expect"))
        continue;

      if (strcasecmp(req->headers[i + 1], "100-continue")) {
        //如果首部name是Expect，但是value不等于100-continue，则返回首部信息有误
        D("SRV: Client(%d) unknown expect header (%s)\n", cl->fd.fd,
          req->headers[i + 1]);

        uh_http_response(cl, 417, "Precondition Failed");
        uh_client_shutdown(cl);
        return;
      } else {
        D("SRV: Client(%d) sending HTTP/1.1 100 Continue\n", cl->fd.fd);

        uh_http_sendf(cl, NULL, "HTTP/1.1 100 Continue\r\n\r\n");
        cl->httpbuf.len = 0; /* client will re-send the body */
        break;
      }
    }

    /* 过滤RFC1918类型的IP */
    if (conf->rfc1918_filter && sa_rfc1918(&cl->peeraddr) &&
        !sa_rfc1918(&cl->servaddr)) {
      uh_http_sendhf(cl, 403, "Forbidden", "Rejected request from RFC1918 IP "
                                           "to public server address");

      uh_client_shutdown(cl);
      return;
    }

    /* 分发请求，做出响应 */
    if (!uh_dispatch_request(cl, req)) {
      D("SRV: Client(%d) failed to dispach request\n", cl->fd.fd);
      uh_client_shutdown(cl);
      return;
    }

    /**
     * 请求处理产生一个CGI响应管道，则注册到监听中
     * 比如：uhttpd_cgi则接收到CGI标准输出后，回调到uh_cgi_socket_cb
     */
    if (cl->rpipe.fd > -1) {
      D("SRV: Client(%d) pipe(%d) spawned\n", cl->fd.fd, cl->rpipe.fd);

      uh_ufd_add(&cl->rpipe, uh_rpipe_cb, ULOOP_READ);
    }

/* request handler spawned a child, register handler */
#if defined(HAVE_CGI) || defined(HAVE_LUA) || defined(HAVE_UBUS)
    if (cl->proc.pid) {
      D("SRV: Client(%d) child(%d) spawned\n", cl->fd.fd, cl->proc.pid);

      /**
       * 记录处理进程(child)
       * 从CGI程序读完了数据之后，它还是不放心，又解析了一下响应头，确认正确之后，才发给了客户端。
       */
      cl->proc.cb = uh_child_cb;
      uloop_process_add(&cl->proc);

      /* 设置脚本超时处理 ,epoll_wait等待时间*/
      cl->timeout.cb = uh_timeout_cb;
      uloop_timeout_set(&cl->timeout, conf->script_timeout * 1000);
    }
#endif

    /* header processing complete */
    D("SRV: Client(%d) dispatched\n", cl->fd.fd);
    cl->dispatched = true;
  }

  //执行响应处理
  if (!cl->cb(cl)) {
    D("SRV: Client(%d) response callback signalized EOF\n", cl->fd.fd);
    //关闭客户端连接
    uh_client_shutdown(cl);
    return;
  }
}

#ifdef HAVE_TLS
/*
  初始化TLS/SSL链接配置
*/
static int uh_inittls(struct config *conf) {
  /* library handle */
  void *lib;

  /* already loaded */
  if (conf->tls != NULL)
    return 0;

  /*
    dlopen用于打开指定名字(filename)的动态链接库，并返回操作句柄。
    load TLS plugin
  */
  if (!(lib = dlopen("uhttpd_tls.so", RTLD_LAZY | RTLD_GLOBAL))) {
    fprintf(stderr,
            "Notice: Unable to load TLS plugin - disabling SSL support! "
            "(Reason: %s)\n",
            dlerror());
    return 1;
  } else {
    /* resolve functions */
    /*
      原型为: void *dlsym(void *handle, char*symbol);
      dlsym根据动态链接库操作句柄(handle)与符号(symbol)，返回符号对应的函数的执行代码地址。
      由此地址，可以带参数执行相应的函数。

      如程序代码:
        void (*add)(int x,int y); //说明一下要调用的动态函数add
        add = dlsym("xxx.so", "add"); //打开xxx.so共享库,取add函数地址
        add(89, 369); //带两个参数89和369调用add函数
    */
    if (!(conf->tls_init = dlsym(lib, "uh_tls_ctx_init")) ||
        !(conf->tls_cert = dlsym(lib, "uh_tls_ctx_cert")) ||
        !(conf->tls_key = dlsym(lib, "uh_tls_ctx_key")) ||
        !(conf->tls_free = dlsym(lib, "uh_tls_ctx_free")) ||
        !(conf->tls_accept = dlsym(lib, "uh_tls_client_accept")) ||
        !(conf->tls_close = dlsym(lib, "uh_tls_client_close")) ||
        !(conf->tls_recv = dlsym(lib, "uh_tls_client_recv")) ||
        !(conf->tls_send = dlsym(lib, "uh_tls_client_send"))) {
      fprintf(stderr, "Error: Failed to lookup required symbols "
                      "in TLS plugin: %s\n",
              dlerror());
      exit(1);
    }

    /* init SSL context */
    if (!(conf->tls = conf->tls_init())) {
      fprintf(stderr, "Error: Failed to initalize SSL context\n");
      exit(1);
    }
  }

  return 0;
}
#endif

#ifdef HAVE_LUA
static int uh_initlua(struct config *conf) {
  /* library handle */
  void *lib;

  /* already loaded */
  if (conf->lua_state != NULL)
    return 0;

  /* load Lua plugin */
  if (!(lib = dlopen("uhttpd_lua.so", RTLD_LAZY | RTLD_GLOBAL))) {
    fprintf(stderr,
            "Notice: Unable to load Lua plugin - disabling Lua support! "
            "(Reason: %s)\n",
            dlerror());

    return 1;
  } else {
    /* resolve functions */
    if (!(conf->lua_init = dlsym(lib, "uh_lua_init")) ||
        !(conf->lua_close = dlsym(lib, "uh_lua_close")) ||
        !(conf->lua_request = dlsym(lib, "uh_lua_request"))) {
      fprintf(stderr, "Error: Failed to lookup required symbols "
                      "in Lua plugin: %s\n",
              dlerror());
      exit(1);
    }

    /* init Lua runtime if handler is specified */
    if (conf->lua_handler) {
      /* default lua prefix */
      if (!conf->lua_prefix)
        conf->lua_prefix = "/lua";

      conf->lua_state = conf->lua_init(conf);
    }
  }

  return 0;
}
#endif

#ifdef HAVE_UBUS
/*
  ubus是新openwrt引入的一个消息总线，主要作用是实现不同应用程序之间的信息交互。
  ubus启动后会在后台运行ubusd进程，该进程监听一个unix套接字用于与其他应用程序通信。其他应用程序
  可基于libubox提供的接口（或自己实现）与其通信。
  使用ubus的方式主要有：
  1、向其注册消息或控制接口。2、向其调用其他应用程序的消息或控制接口。
  3、向其注册监听关心的事件。4、向其发送事件消息。
*/
static int uh_initubus(struct config *conf) {
  /* library handle */
  void *lib;

  /* already loaded */
  if (conf->ubus_state != NULL)
    return 0;

  /* load ubus plugin */
  if (!(lib = dlopen("uhttpd_ubus.so", RTLD_LAZY | RTLD_GLOBAL))) {
    fprintf(stderr,
            "Notice: Unable to load ubus plugin - disabling ubus support! "
            "(Reason: %s)\n",
            dlerror());

    return 1;
  } else if (conf->ubus_prefix) {
    /* resolve functions */
    if (!(conf->ubus_init = dlsym(lib, "uh_ubus_init")) ||
        !(conf->ubus_close = dlsym(lib, "uh_ubus_close")) ||
        !(conf->ubus_request = dlsym(lib, "uh_ubus_request"))) {
      fprintf(stderr, "Error: Failed to lookup required symbols "
                      "in ubus plugin: %s\n",
              dlerror());
      exit(1);
    }

    /* initialize ubus */
    conf->ubus_state = conf->ubus_init(conf);
  }

  return 0;
}
#endif

int main(int argc, char **argv) {

  /* 服务地址结构体 */
  struct addrinfo hints;

  /*
    struct sigaction
    {
        void (*sa_handler) (int);
        sigset_t sa_mask;
        int sa_flags;
        void (*sa_restorer) (void);
    }
    1、sa_handler 此参数和signal()的参数handler 相同, 代表新的信号处理函数,
    其他意义请参考signal().
    2、sa_mask 用来设置在处理该信号时暂时将sa_mask 指定的信号搁置.
    3、sa_restorer 此参数没有使用.
    4、sa_flags 用来设置信号处理的其他相关操作, 下列的数值可用：
      A_NOCLDSTOP: 如果参数signum 为SIGCHLD, 则当子进程暂停时并不会通知父进程
      SA_ONESHOT/SA_RESETHAND: 当调用新的信号处理函数前,
    将此信号处理方式改为系统预设的方式.
      SA_RESTART: 被信号中断的系统调用会自行重启
      SA_NOMASK/SA_NODEFER: 在处理此信号未结束前不理会此信号的再次到来.
    如果参数oldact 不是NULL 指针, 则原来的信号处理方式会由此结构sigaction 返回.
  */
  struct sigaction sa;
  struct config conf;

  /* maximum file descriptor number */
  int cur_fd = 0;

#ifdef HAVE_TLS
  int tls = 0;
  int keys = 0;
#endif

  int bound = 0;

  //默认是后台启动
  int nofork = 0;

  /* args */
  int opt;
  char addr[128];
  char *port = NULL;

  //不做任何相关操作
  sa.sa_flags = 0;

  /*
    sa_mask成员用来指定在信号处理函数执行期间需要被屏蔽的信号，
    特别是当某个信号被处理时，它自身会被自动放入进程的信号掩码，
    因此在信号处理函数执行期间这个信号不会再度发生。

    sigemptyset：信号集初始化并清空
  */
  sigemptyset(&sa.sa_mask);

  /*
    定义函数：int sigaction(int signum, const struct sigaction *act, struct
sigaction *oldact);
    函数说明：sigaction()会依参数signum 指定的信号编号来设置该信号的处理函数.
    参数signum 可以指定SIGKILL 和SIGSTOP 以外的所有信号。

    SIGPIPE：管道破裂: 写一个没有读端口的管道
    SIGINT：键盘中断（如break键被按下）
    SIGTERM：终止信号
 */

  /*
    SIG_ERR  Error return.
    SIG_DFL  Default action.
    SIG_IGN  Ignore signal.
  */
  //忽略管道破裂信号
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);

  //中断以及终止信号执行uh_sigterm方法
  sa.sa_handler = uh_sigterm;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* prepare addrinfo hints */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  /* parse args */
  memset(&conf, 0, sizeof(conf));

  /*
    libubox主要提供以下两种功能：
      1、提供一套基于事件驱动的机制。
      2、提供多种开发支持接口。（如：链表、kv链表、平衡查找二叉树、md5、json）

    uloop有三个功能：
      1、文件描述符触发事件的监控
      2、timeout定时器处理
      3、当前进程的子进程的维护
  */

  //初始化IO模型
  uloop_init();

  //获取运行参数
  while ((opt = getopt(argc, argv,
                       "fSDRC:K:E:I:p:s:h:c:l:L:d:r:m:n:x:i:t:T:A:u:U:")) > 0) {
    switch (opt) {
    /* 设置访问端口 */
    case 'p':
    /* HTTPS访问 */
    case 's':
      memset(addr, 0, sizeof(addr));

      if ((port = strrchr(optarg, ':')) != NULL) {
        if ((optarg[0] == '[') && (port > optarg) && (port[-1] == ']'))
          memcpy(addr, optarg + 1, min(sizeof(addr), (int)(port - optarg) - 2));
        else
          memcpy(addr, optarg, min(sizeof(addr), (int)(port - optarg)));

        port++;
      } else {
        port = optarg;
      }

#ifdef HAVE_TLS
      if (opt == 's') {
        // 初始化TLS/SSL链接配置
        if (uh_inittls(&conf)) {
          fprintf(stderr, "Notice: TLS support is disabled, "
                          "ignoring '-s %s'\n",
                  optarg);
          continue;
        }

        tls = 1;
      }
#endif

      /* bind sockets */
      bound += uh_socket_bind(addr[0] ? addr : NULL, port, &hints, (opt == 's'),
                              &conf);
      break;

#ifdef HAVE_TLS
    /* certificate */
    case 'C':
      /* 初始化证书文件 */
      if (!uh_inittls(&conf)) {
        if (conf.tls_cert(conf.tls, optarg) < 1) {
          fprintf(stderr, "Error: Invalid certificate file given\n");
          exit(1);
        }

        keys++;
      }

      break;

    /* key */
    case 'K':
      /* 初始化私银 */
      if (!uh_inittls(&conf)) {
        if (conf.tls_key(conf.tls, optarg) < 1) {
          fprintf(stderr, "Error: Invalid private key file given\n");
          exit(1);
        }

        keys++;
      }

      break;
#else
    case 'C':
    case 'K':
      fprintf(stderr, "Notice: TLS support not compiled, ignoring -%c\n", opt);
      break;
#endif

    /* docroot */
    case 'h':
      /* 设置WEB根目录 */
      if (!realpath(optarg, conf.docroot)) {
        fprintf(stderr, "Error: Invalid directory %s: %s\n", optarg,
                strerror(errno));
        exit(1);
      }
      break;

    /* error handler */
    case 'E':
      /* 设置异常处理函数 */
      if ((strlen(optarg) == 0) || (optarg[0] != '/')) {
        fprintf(stderr, "Error: Invalid error handler: %s\n", optarg);
        exit(1);
      }
      conf.error_handler = optarg;
      break;

    /* index file */
    case 'I':
      /* 头文件 */
      if ((strlen(optarg) == 0) || (optarg[0] == '/')) {
        fprintf(stderr, "Error: Invalid index page: %s\n", optarg);
        exit(1);
      }
      uh_index_add(optarg);
      break;

    /* don't follow symlinks */
    case 'S':
      //是否跟踪符号链接对应的文件
      conf.no_symlinks = 1;
      break;

    /* don't list directories */
    case 'D':
      //不列出目录文件
      conf.no_dirlists = 1;
      break;

    case 'R':
      //专用网络是指遵守RFC 1918和RFC 4193规范，使用私有IP地址空间的网络
      conf.rfc1918_filter = 1;
      break;

    case 'n':
      //最大请求数
      conf.max_requests = atoi(optarg);
      break;

#ifdef HAVE_CGI
    /* cgi prefix */
    case 'x':
      // CGI前缀设置
      conf.cgi_prefix = optarg;
      break;

    /* interpreter */
    case 'i':
      //解析器设置
      if ((optarg[0] == '.') && (port = strchr(optarg, '='))) {
        *port++ = 0;
        uh_interpreter_add(optarg, port);
      } else {
        fprintf(stderr, "Error: Invalid interpreter: %s\n", optarg);
        exit(1);
      }
      break;
#else
    case 'x':
    case 'i':
      fprintf(stderr, "Notice: CGI support not compiled, ignoring -%c\n", opt);
      break;
#endif

#ifdef HAVE_LUA
    /* lua prefix */
    case 'l':
      // lua前缀
      conf.lua_prefix = optarg;
      break;

    /* lua handler */
    case 'L':
      // lua回调
      conf.lua_handler = optarg;
      break;
#else
    case 'l':
    case 'L':
      fprintf(stderr, "Notice: Lua support not compiled, ignoring -%c\n", opt);
      break;
#endif

#ifdef HAVE_UBUS
    /* ubus prefix */
    case 'u':
      conf.ubus_prefix = optarg;
      break;

    /* ubus socket */
    case 'U':
      conf.ubus_socket = optarg;
      break;
#else
    case 'u':
    case 'U':
      fprintf(stderr, "Notice: UBUS support not compiled, ignoring -%c\n", opt);
      break;
#endif

#if defined(HAVE_CGI) || defined(HAVE_LUA)
    /* script timeout */
    case 't':
      /**
       * 1、脚本超时时间，epoll_wait等待时间
       * 2、post到script的send的等待时间
       */
      conf.script_timeout = atoi(optarg);
      break;
#endif

    /* network timeout */
    case 'T':
      /* 网络超时时间 */
      conf.network_timeout = atoi(optarg);
      break;

    /* tcp keep-alive */
    case 'A':
      /* TCP连接超时时间 */
      conf.tcp_keepalive = atoi(optarg);
      break;

    /* no fork 前台启动 */
    case 'f':
      nofork = 1;
      break;

    /* urldecode */
    case 'd':
      /* url解码指定字符串 */
      if ((port = malloc(strlen(optarg) + 1)) != NULL) {
        /* "decode" plus to space to retain compat */
        for (opt = 0; optarg[opt]; opt++)
          if (optarg[opt] == '+')
            optarg[opt] = ' ';
        /* opt now contains strlen(optarg) -- no need to re-scan */
        memset(port, 0, opt + 1);
        if (uh_urldecode(port, opt, optarg, opt) < 0)
          fprintf(stderr, "uhttpd: invalid encoding\n");

        printf("%s", port);
        free(port);
        exit(0);
      }
      break;

    /* basic auth realm */
    case 'r':
      /* HTTP基础认证设置 路径:用户名:密码 */
      conf.realm = optarg;
      break;

    /* md5 crypt */
    case 'm':
      /* MD5加密 */
      printf("%s\n", crypt(optarg, "$1$"));
      exit(0);
      break;

    /* config file */
    case 'c':
      /* 配置文件路径 */
      conf.file = optarg;
      break;

    default:
      fprintf(stderr,
              "Usage: %s -p [addr:]port [-h docroot]\n"
              "	-f              Do not fork to background\n"
              "	-c file         Configuration file, default is "
              "'/etc/httpd.conf'\n"
              "	-p [addr:]port  Bind to specified address and port, "
              "multiple allowed\n"
#ifdef HAVE_TLS
              "	-s [addr:]port  Like -p but provide HTTPS on this port\n"
              "	-C file         ASN.1 server certificate file\n"
              "	-K file         ASN.1 server private key file\n"
#endif
              "	-h directory    Specify the document root, default is '.'\n"
              "	-E string       Use given virtual URL as 404 error handler\n"
              "	-I string       Use given filename as index for "
              "directories, multiple allowed\n"
              "	-S              Do not follow symbolic links outside of "
              "the docroot\n"
              "	-D              Do not allow directory listings, send "
              "403 instead\n"
              "	-R              Enable RFC1918 filter\n"
              "	-n count        Maximum allowed number of concurrent requests\n"
#ifdef HAVE_LUA
              "	-l string       URL prefix for Lua handler, default is '/lua'\n"
              "	-L file         Lua handler script, omit to disable Lua\n"
#endif
#ifdef HAVE_UBUS
              "	-u string       URL prefix for HTTP/JSON handler\n"
              "	-U file         Override ubus socket path\n"
#endif
#ifdef HAVE_CGI
              "	-x string       URL prefix for CGI handler, default is "
              "'/cgi-bin'\n"
              "	-i .ext=path    Use interpreter at path for files with "
              "the given extension\n"
#endif
#if defined(HAVE_CGI) || defined(HAVE_LUA) || defined(HAVE_UBUS)
              "	-t seconds      CGI, Lua and UBUS script timeout in "
              "seconds, default is 60\n"
#endif
              "	-T seconds      Network timeout in seconds, default is 30\n"
              "	-d string       URL decode given string\n"
              "	-r string       Specify basic auth realm\n"
              "	-m string       MD5 crypt given string\n"
              "\n",
              argv[0]);

      exit(1);
    }
  }

#ifdef HAVE_TLS
  /* 检查SSL初始化是否成功 */
  if ((tls == 1) && (keys < 2)) {
    fprintf(stderr, "Error: Missing private key or certificate file\n");
    exit(1);
  }
#endif

  /* SOCKET是否已开启 */
  if (bound < 1) {
    fprintf(stderr, "Error: No sockets bound, unable to continue\n");
    exit(1);
  }

  /* 检查根目录 */
  if (!conf.docroot[0] && !realpath(".", conf.docroot)) {
    fprintf(stderr, "Error: Can not determine default document root: %s\n",
            strerror(errno));
    exit(1);
  }

  /* 检查授权设置 */
  if (!conf.realm)
    conf.realm = "Protected Area";

  /* 光用命令行的话肯定太麻烦，uhttpd也可以用配置文件来进行配置 */
  uh_config_parse(&conf);

  /* 默认最大请求 */
  if (conf.max_requests <= 0)
    conf.max_requests = 3;

  /* 默认网络超时时间 */
  if (conf.network_timeout <= 0)
    conf.network_timeout = 30;

  /* 访问默认文件 */
  if (!uh_index_files) {
    uh_index_add("index.html");
    uh_index_add("index.htm");
    uh_index_add("default.html");
    uh_index_add("default.htm");
  }

#if defined(HAVE_CGI) || defined(HAVE_LUA) || defined(HAVE_UBUS)
  /* 默认脚本运行时间 */
  if (conf.script_timeout <= 0)
    conf.script_timeout = 60;
#endif

#ifdef HAVE_CGI
  /* 脚本路径前缀 */
  if (!conf.cgi_prefix)
    conf.cgi_prefix = "/cgi-bin";
#endif

#ifdef HAVE_LUA
  /* 初始化LUA */
  if (conf.lua_handler)
    uh_initlua(&conf);
#endif

#ifdef HAVE_UBUS
  /* 初始化ubus客户端 */
  if (conf.ubus_prefix)
    uh_initubus(&conf);
#endif

  /* 如果是后台启动 */
  if (!nofork) {
    switch (fork()) {
    case -1:
      perror("fork()");
      exit(1);

    case 0:
      /*
        守护进程运行在后台，并且不与任何的控制终端连接。守护进程一般在系统启动时启动、以root或者其他特殊的用户运行、处理系统级别的任务。

        守护进程的编写规则：
        1、创建子进程，父进程退出（脱离控制终端），很自然地，子进程成了孤儿进程，被init进程收养。

        2、子进程中创建新会话。
        我们先介绍下进程组的概念：
        进程组是一个或者多个进程的集合，由进程组id来唯一标识，除了进程号PID之外，进程组ID也是一个进程的必备属性。
        每个进程组都有一个组长进程，其组长进程的进程号PID等于进程组ID，且该进程ID不会因为组长进程的退出而受到影响。
        会话组是一个或者多个进程组的集合，通常，一个会话开始于用户登录，终止于用户退出，在此期间用户运行的所有进程都属于这个会话期。
        Setid函数就是用于创建一个新的会话，并担任该会话组的组长，有三个作用，让进程摆脱原会话和进程组，终端的控制，使进程完全独立出来。

        3、由于fork（）继承了父进程的工作目录，避免以后的使用造成不便，所以我们要改变当前目录为根目录。
        4、重设文件权限掩码。 Umask（0）
        5、关闭文件描述符。 （fork（）继承过来的）
      */

      //创建守护进程
      if (chdir("/"))
        perror("chdir()");

      /**
       * 标准输入、标准输出和标准出错处理。这三个文件分别对应文件描述符0、1、2
       * dup2()用来复制参数oldfd 所指的文件描述词,
       * 并将它拷贝至参数newfd后一块返回
       *
       * 某些守护进程打开/dev/null使其具有文件描述符0，1，2这样任何一个试图读标准输入、
       * 写标准输出或标准出错的库历程都不会产生任何效果。
       *
       * O_WRONLY 以只写方式打开文件
       */
      if ((cur_fd = open("/dev/null", O_WRONLY)) > -1)
        dup2(cur_fd, 0);

      // O_RDONLY 以只读方式打开文件
      if ((cur_fd = open("/dev/null", O_RDONLY)) > -1)
        dup2(cur_fd, 1);

      if ((cur_fd = open("/dev/null", O_RDONLY)) > -1)
        dup2(cur_fd, 2);

      break;

    default:
      exit(0);
    }
  }

  /* 事件循环主处理入口 */
  uloop_run();

#ifdef HAVE_LUA
  /* destroy the Lua state */
  if (conf.lua_state != NULL)
    conf.lua_close(conf.lua_state);
#endif

#ifdef HAVE_UBUS
  /* destroy the ubus state */
  if (conf.ubus_state != NULL)
    conf.ubus_close(conf.ubus_state);
#endif

  return 0;
}
