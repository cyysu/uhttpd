/*
 * uhttpd - Tiny single-threaded httpd - CGI handler
 *
 * uhttpd采用了管道和CGI程序进行通信，有两个管道，实现双向通信。
 * 一个管道负责从父进程写数据到CGI程序，主要是客户端的POST数据。
 * 另一个就是读取CGI程序的处理结果。同时，按照CGI的标准，
 * HTTP请求头都是通过环境变量的方式传给CGI程序的，CGI程序是fork和exec的，
 * 所以会继承环境变量，达到传递数据的目的。
 *
 *   Copyright (C) 2010-2012 Jo-Philipp Wich <xm@subsignal.org>
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

#include "uhttpd-utils.h"

#include "uhttpd-cgi.h"

/**
 * CGI响应头部解析
 */
static bool uh_cgi_header_parse(struct http_response *res, char *buf, int len,
                                int *off) {
  char *bufptr = NULL;
  char *hdrname = NULL;
  int hdrcount = 0;
  int pos = 0;

  D("SRV: try parse cgi header (%s)\n", buf);

  /* 查找响应格式的换行位置 */
  if (((bufptr = strfind(buf, len, "\r\n\r\n", 4)) != NULL) ||
      ((bufptr = strfind(buf, len, "\n\n", 2)) != NULL)) {

    //定位到响应首部的结尾（即body开始位置）
    *off = (int)(bufptr - buf) + ((bufptr[0] == '\r') ? 4 : 2);

    memset(res, 0, sizeof(*res));

    res->statuscode = 200;
    res->statusmsg = "OK";

    bufptr = &buf[0];

    for (pos = 0; pos < *off; pos++) {
      if (!hdrname && (buf[pos] == ':')) {
        /* 冒号替换成0 */
        buf[pos++] = 0;

        if ((pos < len) && (buf[pos] == ' '))
          pos++;

        if (pos < len) {
          /* 指向首部KEY */
          hdrname = bufptr;
          /* 指向首部VALUE */
          bufptr = &buf[pos];
        }
      }

      else if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
        if (!hdrname)
          break;

        /* 换行符替换成0 */
        buf[pos++] = 0;

        if ((pos < len) && (buf[pos] == '\n'))
          pos++;

        if (pos <= len) {
          /* 检查首部个数是否在res->hearders范围内 */
          if ((hdrcount + 1) < array_size(res->headers)) {

            /* Status首部设置响应状态以及响应信息（uhttpd特有？） */
            if (!strcasecmp(hdrname, "Status")) {
              res->statuscode = atoi(bufptr);

              if (res->statuscode < 100)
                res->statuscode = 200;

              if (((bufptr = strchr(bufptr, ' ')) != NULL) &&
                  (&bufptr[1] != 0)) {
                res->statusmsg = &bufptr[1];
              }

              D("CGI: HTTP/1.x %03d %s\n", res->statuscode, res->statusmsg);
            } else {
              D("CGI: HTTP: %s: %s\n", hdrname, bufptr);

              res->headers[hdrcount++] = hdrname;
              res->headers[hdrcount++] = bufptr;
            }

            /* 指向到下一个首部 */
            bufptr = &buf[pos];
            hdrname = NULL;
          } else {
            return false;
          }
        }
      }
    }

    return true;
  }

  return false;
}

static char *uh_cgi_header_lookup(struct http_response *res,
                                  const char *hdrname) {
  int i;

  foreach_header(i, res->headers) {
    if (!strcasecmp(res->headers[i], hdrname))
      return res->headers[i + 1];
  }

  return NULL;
}

static void uh_cgi_shutdown(struct uh_cgi_state *state) { free(state); }

/**
 * CGI处理回调（响应）
 */
static bool uh_cgi_socket_cb(struct client *cl) {
  int i, len, blen, hdroff;
  char buf[UH_LIMIT_MSGHEAD];
  // CGI状态信息
  struct uh_cgi_state *state = (struct uh_cgi_state *)cl->priv;
  struct http_response *res = &cl->response;
  struct http_request *req = &cl->request;

  /* 存在POST数据则传到CGI */
  while (state->content_length > 0) {
    /* remaining data in http head buffer ... */
    if (cl->httpbuf.len > 0) {
      len = min(state->content_length, cl->httpbuf.len);

      D("CGI: Child(%d) feed %d HTTP buffer bytes\n", cl->proc.pid, len);

      memcpy(buf, cl->httpbuf.ptr, len);

      cl->httpbuf.len -= len;
      cl->httpbuf.ptr += len;
    }

    /* 如果请求Content-Type是有值的，但是还没获取到httpbuf中，则尝试再次从socket中读取
       */
    else {
      len = uh_tcp_recv(cl, buf, min(state->content_length, sizeof(buf)));

      if ((len < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
        break;

      D("CGI: Child(%d) feed %d/%d TCP socket bytes\n", cl->proc.pid, len,
        min(state->content_length, sizeof(buf)));
    }

    if (len)
      state->content_length -= len;
    else
      state->content_length = 0;

    printf("POST DATA:%s\n", buf);
    printf("POST LEN:%d\n", len);

    /**
     * 将POST数据传给CGI脚本
     * script_timeout等待时间
     */
    len = uh_raw_send(cl->wpipe.fd, buf, len, cl->server->conf->script_timeout);

    /* explicit EOF notification for the child */
    if (state->content_length <= 0)
      uh_ufd_remove(&cl->wpipe);
  }

  /* 获取子进程执行CGI脚本后的输出 */
  while ((len = uh_raw_recv(
              cl->rpipe.fd, buf,
              state->header_sent ? sizeof(buf) : state->httpbuf.len, -1)) > 0) {
    /**
     * 先进行响应头部的解析
     * 当CGI执行程序没有封装好CGI协议内容，则必须自行输出响应头部
     * 1、使用了/usr/bin/php运行php程序，则相当于命令行模式，必须自行输出响应头部，再输出内容
     * 2、使用了/usr/bin/php-cgi运行php程序，则php-cgi中已自动封装好请求报文以及响应报文，
     *   即可使用封装好的全局变量$_POST,$_SERVER等，响应直接输出即可
     */
    if (!state->header_sent) {
      /* try to parse header ... */
      memcpy(state->httpbuf.ptr, buf, len);
      state->httpbuf.len -= len;
      state->httpbuf.ptr += len;

      /* 响应文本的长度 */
      blen = state->httpbuf.ptr - state->httpbuf.buf;

      /* CGI响应头部解析 */
      if (uh_cgi_header_parse(res, state->httpbuf.buf, blen, &hdroff)) {
        /* write status */
        ensure_out(uh_http_sendf(cl, NULL, "%s %03d %s\r\n"
                                           "Connection: close\r\n",
                                 http_versions[req->version], res->statuscode,
                                 res->statusmsg));

        /* add Content-Type if no Location or Content-Type */
        if (!uh_cgi_header_lookup(res, "Location") &&
            !uh_cgi_header_lookup(res, "Content-Type")) {
          ensure_out(
              uh_http_send(cl, NULL, "Content-Type: text/plain\r\n", -1));
        }

        /* if request was HTTP 1.1 we'll respond chunked */
        if ((req->version > UH_HTTP_VER_1_0) &&
            !uh_cgi_header_lookup(res, "Transfer-Encoding")) {
          ensure_out(
              uh_http_send(cl, NULL, "Transfer-Encoding: chunked\r\n", -1));
        }

        /* write headers from CGI program */
        foreach_header(i, res->headers) {
          ensure_out(uh_http_sendf(cl, NULL, "%s: %s\r\n", res->headers[i],
                                   res->headers[i + 1]));
        }

        /* terminate header */
        ensure_out(uh_http_send(cl, NULL, "\r\n", -1));

        state->header_sent = true;

        /* push out remaining head buffer */
        if (hdroff < blen) {
          D("CGI: Child(%d) relaying %d rest bytes\n", cl->proc.pid,
            blen - hdroff);

          ensure_out(uh_http_send(cl, req, state->httpbuf.buf + hdroff,
                                  blen - hdroff));
        }
      }

      /* 如果读取到的响应内容超出到了httpbuf的大小 */
      else if (!state->httpbuf.len) {
        /* I would do this ...
         *
         *    uh_cgi_error_500(cl, req,
         *        "The CGI program generated an "
         *        "invalid response:\n\n");
         *
         * ... but in order to stay as compatible(兼容的) as possible,
         * treat whatever we got as text/plain response and
         * build the required headers here.
         */

        ensure_out(uh_http_sendf(cl, NULL, "%s 200 OK\r\n"
                                           "Content-Type: text/plain\r\n"
                                           "%s\r\n",
                                 http_versions[req->version],
                                 (req->version > UH_HTTP_VER_1_0)
                                     ? "Transfer-Encoding: chunked\r\n"
                                     : ""));

        state->header_sent = true;

        D("CGI: Child(%d) relaying %d invalid bytes\n", cl->proc.pid, len);

        ensure_out(uh_http_send(cl, req, buf, len));
      }
    } else {
      /* 响应首部完成后传输响应body */
      D("CGI: Child(%d) relaying %d normal bytes\n", cl->proc.pid, len);
      ensure_out(uh_http_send(cl, req, buf, len));
    }
  }

  /**
   * 读到了EOF或者读取中发生错误
   * EOF（End Of File），在操作系统中表示资料源无更多的资料可读取
   */
  if ((len == 0) ||
      ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (len == -1))) {
    D("CGI: Child(%d) presumed dead [%s]\n", cl->proc.pid, strerror(errno));

    goto out;
  }

  return true;

out:
  // 如果CGI没有首部输出
  if (!state->header_sent) {
    if (cl->timeout.pending) {
      uh_http_sendhf(cl, 502, "Bad Gateway",
                     "The CGI process did not produce any response\n");
    } else {
      uh_http_sendhf(cl, 504, "Gateway Timeout",
                     "The CGI process took too long to produce a "
                     "response\n");
    }
  } else {
    uh_http_send(cl, req, "", 0);
  }

  uh_cgi_shutdown(state);
  return false;
}

/**
 * CGI请求处理
 */
bool uh_cgi_request(struct client *cl, struct path_info *pi,
                    struct interpreter *ip) {
  int i;

  int rfd[2] = {0, 0};
  int wfd[2] = {0, 0};

  pid_t child;

  struct uh_cgi_state *state;
  struct http_request *req = &cl->request;

  /* allocate state */
  if (!(state = malloc(sizeof(*state)))) {
    uh_http_sendhf(cl, 500, "Internal Server Error", "Out of memory");
    return false;
  }

  /**
   * spawn pipes for me->child, child->me
   *
   * 管道是半双工的：半双工（half-duplex）的系统允许二台设备之间的双向数据传输，但不能同时进行
   * 由描述字fd[0]表示，称其为管道读端；另一端则只能用于写，由描述字fd[1]来表示，称其为管道写端
   */
  if ((pipe(rfd) < 0) || (pipe(wfd) < 0)) {
    if (rfd[0] > 0)
      close(rfd[0]);
    if (rfd[1] > 0)
      close(rfd[1]);
    if (wfd[0] > 0)
      close(wfd[0]);
    if (wfd[1] > 0)
      close(wfd[1]);

    uh_http_sendhf(cl, 500, "Internal Server Error",
                   "Failed to create pipe: %s\n", strerror(errno));

    return false;
  }

  /**
   * 函数原型：pid_t fork(void);
   * 返回值： 若成功调用一次则返回两个值，子进程返回0，父进程返回子进程ID；
   * 否则，出错返回-1
   */
  switch ((child = fork())) {
  /* oops */
  case -1:
    uh_http_sendhf(cl, 500, "Internal Server Error",
                   "Failed to fork child: %s\n", strerror(errno));

    return false;

  /* 执行子进程 */
  case 0:
#ifdef DEBUG
    sleep(atoi(getenv("UHTTPD_SLEEP_ON_FORK") ?: "0"));
#endif

    /* do not leak(泄露) parent epoll descriptor(描述符) */
    uloop_done();

    /* close loose pipe ends */
    close(rfd[0]);
    close(wfd[1]);

    /* 标准输出绑定到管道写端*/
    dup2(rfd[1], 1);
    /* 标准输入绑定到管道读端 */
    dup2(wfd[0], 0);

    /**
     * 我们经常会碰到需要fork子进程的情况，而且子进程很可能会继续exec新的程序
     * 一般我们会调用exec执行另一个程序，此时会用全新的程序替换子进程的正文，数据，堆和栈等。
     * 此时保存文件描述符的变量当然也不存在了，我们就无法关闭无用的文件描述符了（内存泄露）。
     * 所以通常我们会fork子进程后在子进程中直接执行close关掉无用的文件描述符，然后再执行exec。
     * 但是在复杂系统中，有时我们fork子进程时已经不知道打开了多少个文件描述符
     * （包括socket句柄等），这此时进行逐一清理确实有很大难度。
     * 我们期望的是能在fork子进程前打开某个文件句柄时就指定好：“这个句柄我在fork子进程后执行exec时就关闭”。
     * 其实时有这样的方法的：即所谓的 close-on-exec。
     */
    fd_cloexec(rfd[1]);
    fd_cloexec(wfd[0]);

    /* 检查是否为可执行的一般文件或者解析器 */
    if (((pi->stat.st_mode & S_IFREG) && (pi->stat.st_mode & S_IXOTH)) ||
        (ip != NULL)) {
      /* build environment */
      clearenv();

      /**
       * setenv()用来改变或增加环境变量的内容
       * 每个进程都有其各自的环境变量设置
       * 当一个进程被创建时，
       * 除了创建过程中的明确更改外，它继承了其父进程的绝大部分环境设置
       *
       * 环境变量是包含诸如驱动器、路径或文件名之类的字符串。环境变量控制着多种程序的行为。
       * http正文部分作为CGI脚本的标准输入，也就意味着POST请求的参数也是通过标准输入。
       * 请求的其他信息都是通过环境变量的方式传入CGI脚本
       */
      setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
      setenv("SERVER_SOFTWARE", "uHTTPd", 1);
      setenv("PATH", "/sbin:/usr/sbin:/bin:/usr/bin", 1);

#ifdef HAVE_TLS
      /* https? */
      if (cl->tls)
        setenv("HTTPS", "on", 1);
#endif

      /* addresses */
      setenv("SERVER_NAME", sa_straddr(&cl->servaddr), 1);
      setenv("SERVER_ADDR", sa_straddr(&cl->servaddr), 1);
      setenv("SERVER_PORT", sa_strport(&cl->servaddr), 1);
      setenv("REMOTE_HOST", sa_straddr(&cl->peeraddr), 1);
      setenv("REMOTE_ADDR", sa_straddr(&cl->peeraddr), 1);
      setenv("REMOTE_PORT", sa_strport(&cl->peeraddr), 1);

      /* path information */
      setenv("SCRIPT_NAME", pi->name, 1);
      setenv("SCRIPT_FILENAME", pi->phys, 1);
      setenv("DOCUMENT_ROOT", pi->root, 1);
      setenv("QUERY_STRING", pi->query ? pi->query : "", 1);

      if (pi->info)
        setenv("PATH_INFO", pi->info, 1);

      /* REDIRECT_STATUS, php-cgi wants it */
      switch (req->redirect_status) {
      case 404:
        setenv("REDIRECT_STATUS", "404", 1);
        break;

      default:
        setenv("REDIRECT_STATUS", "200", 1);
        break;
      }

      /* http version */
      setenv("SERVER_PROTOCOL", http_versions[req->version], 1);

      /* request method */
      setenv("REQUEST_METHOD", http_methods[req->method], 1);

      /* request url */
      setenv("REQUEST_URI", req->url, 1);

      /* remote user */
      if (req->realm)
        setenv("REMOTE_USER", req->realm->user, 1);

      /* request message headers */
      foreach_header(i, req->headers) {
        if (!strcasecmp(req->headers[i], "Accept"))
          setenv("HTTP_ACCEPT", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Accept-Charset"))
          setenv("HTTP_ACCEPT_CHARSET", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Accept-Encoding"))
          setenv("HTTP_ACCEPT_ENCODING", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Accept-Language"))
          setenv("HTTP_ACCEPT_LANGUAGE", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Authorization"))
          setenv("HTTP_AUTHORIZATION", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Connection"))
          setenv("HTTP_CONNECTION", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Cookie"))
          setenv("HTTP_COOKIE", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Host"))
          setenv("HTTP_HOST", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Referer"))
          setenv("HTTP_REFERER", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "User-Agent"))
          setenv("HTTP_USER_AGENT", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Content-Type"))
          setenv("CONTENT_TYPE", req->headers[i + 1], 1);

        else if (!strcasecmp(req->headers[i], "Content-Length"))
          setenv("CONTENT_LENGTH", req->headers[i + 1], 1);
      }

      /**
       * execute child code ...
       * chdir函数用于改变当前工作目录
       */
      if (chdir(pi->root))
        perror("chdir()");

      /**
       * 使用exec会在当前的进程空间创建一个子进程，然后终止当前线程的执行，
       * 到了新建的线程执行完之后，其实两个线程都终止了，也就是这个当前shell进程也就终止了
       * 因为exec运行新的程序后会覆盖从父进程继承来的存储映像，那么信号捕捉函数在新程序中已无意义，
       * 原进程确实将环境变量信息传递给了新进程
       *
       * php-cgi在POST请求中，收到CONTENT_TYPE等于application/x-www-form-urlencoded报头后，
       * 会根据CONTENT_LENGTH报头的长度获取POST的数据。
       * 注意：CGI会通过阻塞的方式直到完全获取CONTENT_LENGTH长度的数据
       */
      if (ip != NULL)
        execl(ip->path, ip->path, pi->phys, NULL);
      else
        execl(pi->phys, pi->phys, NULL);

      /* in case it fails ... */
      printf("Status: 500 Internal Server Error\r\n\r\n"
             "Unable to launch the requested CGI program:\n"
             "  %s: %s\n",
             ip ? ip->path : pi->phys, strerror(errno));
    }

    /* 403 */
    else {
      printf("Status: 403 Forbidden\r\n\r\n"
             "Access to this resource is forbidden\n");
    }

    close(wfd[0]);
    close(rfd[1]);
    exit(0);

    break;

  /* parent; handle I/O relaying */
  default:
    memset(state, 0, sizeof(*state));

    /* rfd[1]绑定到子进程的标准输出 */
    cl->rpipe.fd = rfd[0];
    /* wfd[0]绑定到子进程的标准输入 */
    cl->wpipe.fd = wfd[1];
    /* child子进程ID */
    cl->proc.pid = child;

    /* make pipe non-blocking */
    fd_nonblock(cl->rpipe.fd);
    fd_nonblock(cl->wpipe.fd);

    /* close unneeded pipe ends */
    close(rfd[1]);
    close(wfd[0]);

    D("CGI: Child(%d) created: rfd(%d) wfd(%d)\n", child, rfd[0], wfd[1]);

    state->httpbuf.ptr = state->httpbuf.buf;
    state->httpbuf.len = sizeof(state->httpbuf.buf);

    /* 设置为请求正文长度 */
    state->content_length = cl->httpbuf.len;

    /* 如果是POST方法，以首部Content-Length定义的长度为准 */
    if (req->method == UH_HTTP_MSG_POST) {
      foreach_header(i, req->headers) {
        if (!strcasecmp(req->headers[i], "Content-Length")) {
          state->content_length = atoi(req->headers[i + 1]);
          break;
        }
      }
    }

    cl->cb = uh_cgi_socket_cb;
    /* CGI状态信息 */
    cl->priv = state;

    break;
  }

  return true;
}
