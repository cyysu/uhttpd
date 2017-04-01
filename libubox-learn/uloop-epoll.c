/*
 * epoll是在高效的***IO复用技术***
 * 所谓的IO复用，多路连接复用一个IO线程
 * 常见的IO复用技术有select, poll,
 * epoll以及kqueue等等。其中epoll为Linux独占，而kqueue则在许多UNIX系统上存在，包括OS
 * X
 *
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2016 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * FIXME: uClibc < 0.9.30.3 does not define EPOLLRDHUP for Linux >= 2.6.17
 */
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

/*
  初始化epoll多路复用
  主要工作是poll_fd =
  epoll_create(32);创建一个epoll的文件描述符监控句柄。最多监控32个文件描述符
*/
static int uloop_init_pollfd(void) {
  if (poll_fd >= 0)
    return 0;

  poll_fd = epoll_create(32);
  if (poll_fd < 0)
    return -1;

  /*
    fcntl()用来操作文件描述词的一些特性
    F_SETFD 设置close-on-exec 旗标. 该旗标以参数arg 的FD_CLOEXEC 位决定.
    F_GETFD
    取得与文件描述符fd联合close-on-exec标志,类似FD_CLOEXEC.如果返回值和FD_CLOEXEC进行与运算结果是0的话,文件保持交叉式访问exec(),否则如果通过exec运行的话,文件将被关闭(arg被忽略)

    close-on-exec:这个句柄我在fork子进程后执行exec时就关闭
  */
  fcntl(poll_fd, F_SETFD, fcntl(poll_fd, F_GETFD) | FD_CLOEXEC);
  return 0;
}

/**
 * 注册epoll配置
 */
static int register_poll(struct uloop_fd *fd, unsigned int flags) {
  struct epoll_event ev;
  int op = fd->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

  memset(&ev, 0, sizeof(struct epoll_event));

  /* 设置监听读事件 */
  if (flags & ULOOP_READ)
    ev.events |= EPOLLIN | EPOLLRDHUP;

  /* 设置监听写事件 */
  if (flags & ULOOP_WRITE)
    ev.events |= EPOLLOUT;

  /* 设置是否为ET模式 */
  if (flags & ULOOP_EDGE_TRIGGER)
    ev.events |= EPOLLET;

  ev.data.ptr = fd;
  fd->flags = flags;

  return epoll_ctl(poll_fd, op, fd->fd, &ev);
}

static struct epoll_event events[ULOOP_MAX_EVENTS];

static int __uloop_fd_delete(struct uloop_fd *sock) {
  sock->flags = 0;
  return epoll_ctl(poll_fd, EPOLL_CTL_DEL, sock->fd, 0);
}

/**
 * 将epoll监听到的事件封装到全局变量cur_fds
 *
 * 为什么还要封装一层？
 * 因为IO模型可能有多种，epoll只是其中一种
 * 封装好之后让uloop.c统一处理
 */
static int uloop_fetch_events(int timeout) {
  int n, nfds;

  fprintf(stderr, "SRV: epoll wait %d\n", timeout);

  nfds = epoll_wait(poll_fd, events, ARRAY_SIZE(events), timeout);
  for (n = 0; n < nfds; ++n) {
    struct uloop_fd_event *cur = &cur_fds[n];
    struct uloop_fd *u = events[n].data.ptr;
    unsigned int ev = 0;

    cur->fd = u;
    if (!u)
      continue;

    /**
     * EPOLLERR：表示对应的文件描述符发生错误；
     * EPOLLHUP：表示对应的文件描述符被挂断；
     * epoll发生错误
     */
    if (events[n].events & (EPOLLERR | EPOLLHUP)) {
      u->error = true;
      if (!(u->flags & ULOOP_ERROR_CB))
        uloop_fd_delete(u);
    }

    /**
     * 监听描述符事件有误
     */
    if (!(events[n].events &
          (EPOLLRDHUP | EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP))) {
      cur->fd = NULL;
      continue;
    }

    if (events[n].events & EPOLLRDHUP)
      u->eof = true;

    // EPOLLIN ：表示对应的文件描述符可以读
    if (events[n].events & EPOLLIN)
      ev |= ULOOP_READ;

    // EPOLLOUT：表示对应的文件描述符可以写
    if (events[n].events & EPOLLOUT)
      ev |= ULOOP_WRITE;

    cur->events = ev;
  }

  return nfds;
}
