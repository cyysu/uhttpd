/*
 * uloop - event loop implementation
 *
 * uloop主要工能有下例3个
 * 文件描述符触发事件的监控 (即uloop_run_events)
 * - 循环调用epoll_wait 监相应的触发事件文件描述符fd
 * - timeout定时器处理(即uloop_process_timeouts)
 * - 当前进程的子进程的维护(即uloop_handle_processes)
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
#include <sys/time.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uloop.h"
#include "utils.h"

#ifdef USE_KQUEUE
#include <sys/event.h>
#endif
#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif
#include <sys/wait.h>

struct uloop_fd_event {
  struct uloop_fd *fd;
  unsigned int events;
};

struct uloop_fd_stack {
  struct uloop_fd_stack *next;
  struct uloop_fd *fd;
  unsigned int events;
};

static struct uloop_fd_stack *fd_stack = NULL;

#define ULOOP_MAX_EVENTS 10

static struct list_head timeouts = LIST_HEAD_INIT(timeouts);
static struct list_head processes = LIST_HEAD_INIT(processes);

static int poll_fd = -1;
bool uloop_cancelled = false;
static int uloop_status = 0;
static bool do_sigchld = false;

//记录当前处理中的文件描述符
static struct uloop_fd_event cur_fds[ULOOP_MAX_EVENTS];
static int cur_fd, cur_nfds;
static int uloop_run_depth = 0;

int uloop_fd_add(struct uloop_fd *sock, unsigned int flags);

#ifdef USE_KQUEUE
#include "uloop-kqueue.c"
#endif

#ifdef USE_EPOLL
#include "uloop-epoll.c"
#endif

static void waker_consume(struct uloop_fd *fd, unsigned int events) {
  char buf[4];

  while (read(fd->fd, buf, 4) > 0) {
    fprintf(stderr, "waker_consume: read %s\n", buf);
  }
}

// waker_pipe究竟有什么用？？？
static int waker_pipe = -1;
static struct uloop_fd waker_fd = {
    .fd = -1, .cb = waker_consume,
};

static void waker_init_fd(int fd) {
  /**
   * exec用被执行的程序完全替换调用它的程序的影像
   * fork创建一个新的进程就产生了一个新的PID，exec启动一个新程序，替换原有的进程
   * 因此这个新的被exec执行的进程的PID不会改变，和调用exec函数的进程一样
   *
   * FD_CLOEXEC表示当程序执行exec函数时本fd将被系统自动关闭,表示不传递给exec创建的新进程
   */
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
  // 设置为非阻塞方式
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static int waker_init(void) {
  int fds[2];

  if (waker_pipe >= 0)
    return 0;

  /**
   * 管道对于管道两端的进程而言，就是一个文件，但它不是普通的文件，它不属于某种文件系统，
   * 而是自立门户，单独构成一种文件系统，并且只存在于内存中
   */
  if (pipe(fds) < 0)
    return -1;

  waker_init_fd(fds[0]);
  waker_init_fd(fds[1]);
  waker_pipe = fds[1];

  waker_fd.fd = fds[0];
  waker_fd.cb = waker_consume;

  //注册到uloop
  uloop_fd_add(&waker_fd, ULOOP_READ);

  return 0;
}

/**
 * 初始化事件循环
 */
int uloop_init(void) {
  if (uloop_init_pollfd() < 0)
    return -1;

  if (waker_init() < 0) {
    uloop_done();
    return -1;
  }

  return 0;
}

/**
 * For every entry in cur_fds array,
 * uloop will check whether the event is level trigger or edge trigger.
 * If the event is edge triggering, uloop will check every entry inside fd_stack
 * list.
 * If there is already an exsiting entry with the same file descriptor fd,
 * and the event will be buffered and kept in fd_stack list with
 * ULOOP_EVENT_BUFFERED set. In this case, uloop_fd_stack_event() returns true.
 */
static bool uloop_fd_stack_event(struct uloop_fd *fd, int events) {
  struct uloop_fd_stack *cur;

  /*
   * Do not buffer events for level-triggered fds, they will keep firing.
   * Caller needs to take care of recursion issues.
   *
   * flags中是否设置了ET模式
   */
  if (!(fd->flags & ULOOP_EDGE_TRIGGER))
    return false;

  for (cur = fd_stack; cur; cur = cur->next) {
    if (cur->fd != fd)
      continue;

    if (events < 0) {
      cur->fd = NULL;
    } else {
      //加上ULOOP_EVENT_BUFFERED事件
      cur->events |= events | ULOOP_EVENT_BUFFERED;
    }

    return true;
  }

  return false;
}

static void uloop_run_events(int timeout) {
  struct uloop_fd_event *cur;
  struct uloop_fd *fd;

  if (!cur_nfds) {
    cur_fd = 0;
    //在最新设置的超时时间内获取监听到的文件描述符
    cur_nfds = uloop_fetch_events(timeout);
    if (cur_nfds < 0)
      cur_nfds = 0;
  }

  //触发uloop_fetch_events过滤后的文件描述符的处理函数
  while (cur_nfds > 0) {
    struct uloop_fd_stack stack_cur;
    unsigned int events;

    cur = &cur_fds[cur_fd++];
    cur_nfds--;

    fd = cur->fd;
    events = cur->events;
    if (!fd)
      continue;

    //是否绑定了描述符事件处理函数
    if (!fd->cb)
      continue;

    if (uloop_fd_stack_event(fd, cur->events))
      continue;

    stack_cur.next = fd_stack;
    stack_cur.fd = fd;
    fd_stack = &stack_cur;
    do {
      stack_cur.events = 0;
      fd->cb(fd, events);
      events = stack_cur.events & ULOOP_EVENT_MASK;
    } while (stack_cur.fd && events);
    fd_stack = stack_cur.next;

    return;
  }
}

/**
 * 注册描述符到IO模型中
 * 未有EPOLLET配置，使用的是LT模式
 */
int uloop_fd_add(struct uloop_fd *sock, unsigned int flags) {
  unsigned int fl;
  int ret;

  /* 事件既不是读也不是写则删除该描述符 */
  if (!(flags & (ULOOP_READ | ULOOP_WRITE)))
    return uloop_fd_delete(sock);

  if (!sock->registered && !(flags & ULOOP_BLOCKING)) {
    fl = fcntl(sock->fd, F_GETFL, 0);
    fl |= O_NONBLOCK;
    fcntl(sock->fd, F_SETFL, fl);
  }

  //注册IO模型配置
  ret = register_poll(sock, flags);
  if (ret < 0)
    goto out;

  sock->registered = true;
  sock->eof = false;
  sock->error = false;

out:
  return ret;
}

/*
  从事件处理循环中销毁指定描述符
*/
int uloop_fd_delete(struct uloop_fd *fd) {
  int i;

  for (i = 0; i < cur_nfds; i++) {
    if (cur_fds[cur_fd + i].fd != fd)
      continue;

    cur_fds[cur_fd + i].fd = NULL;
  }

  if (!fd->registered)
    return 0;

  fd->registered = false;
  uloop_fd_stack_event(fd, -1);
  return __uloop_fd_delete(fd);
}

static int tv_diff(struct timeval *t1, struct timeval *t2) {
  return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_usec - t2->tv_usec) / 1000;
}

/**
 * 循环获取当前时间，把超时的timeout处理掉，有一条timeout链表在维护（即静态struct
 * list_head超时）
 */
int uloop_timeout_add(struct uloop_timeout *timeout) {
  struct uloop_timeout *tmp;
  struct list_head *h = &timeouts;

  if (timeout->pending)
    return -1;

  //按照超时时间小到大排序
  list_for_each_entry(tmp, &timeouts, list) {
    if (tv_diff(&tmp->time, &timeout->time) > 0) {
      h = &tmp->list;
      break;
    }
  }

  list_add_tail(&timeout->list, h);
  timeout->pending = true;

  return 0;
}

/*
  获取当前时间
*/
static void uloop_gettime(struct timeval *tv) {
  struct timespec ts;

  /*
    函数"clock_gettime"是基于Linux C语言的时间函数,他可以用于计算精度和纳秒
    CLOCK_MONOTONIC:从系统启动这一刻起开始计时,不受系统时间被用户改变的影响
  */
  clock_gettime(CLOCK_MONOTONIC, &ts);
  tv->tv_sec = ts.tv_sec;
  // tv_usec为微秒数，即秒后面的零头
  tv->tv_usec = ts.tv_nsec / 1000;
}

int uloop_timeout_set(struct uloop_timeout *timeout, int msecs) {
  struct timeval *time = &timeout->time;

  if (timeout->pending)
    uloop_timeout_cancel(timeout);

  uloop_gettime(time);

  time->tv_sec += msecs / 1000;
  time->tv_usec += (msecs % 1000) * 1000;

  if (time->tv_usec > 1000000) {
    time->tv_sec++;
    time->tv_usec -= 1000000;
  }

  return uloop_timeout_add(timeout);
}

/**
 * 销毁指定定时器
 */
int uloop_timeout_cancel(struct uloop_timeout *timeout) {
  if (!timeout->pending)
    return -1;

  list_del(&timeout->list);
  timeout->pending = false;

  return 0;
}

/**
 * 获取定时器还剩多长时间超时
 */
int uloop_timeout_remaining(struct uloop_timeout *timeout) {
  struct timeval now;

  if (!timeout->pending)
    return -1;

  uloop_gettime(&now);

  return tv_diff(&timeout->time, &now);
}

/**
 * 循环检测是否收到一个sigchld信号，如果收到，删除对应的子进程，
 * 有一条过程子进程链表在维护（即静态struct list_head进程）
 */
int uloop_process_add(struct uloop_process *p) {
  struct uloop_process *tmp;
  struct list_head *h = &processes;

  if (p->pending)
    return -1;

  //按照pid小到大排序
  list_for_each_entry(tmp, &processes, list) {
    if (tmp->pid > p->pid) {
      h = &tmp->list;
      break;
    }
  }

  list_add_tail(&p->list, h);
  p->pending = true;

  return 0;
}

/**
 * 从事件处理循环中销毁指定进程
 */
int uloop_process_delete(struct uloop_process *p) {
  if (!p->pending)
    return -1;

  list_del(&p->list);
  p->pending = false;

  return 0;
}

/**
 * 处理结束进程
 */
static void uloop_handle_processes(void) {
  struct uloop_process *p, *tmp;
  pid_t pid;
  int ret;

  do_sigchld = false;

  while (1) {
    /**
     * 定义函数：pid_t waitpid(pid_t pid, int * status, int options);
     * 函数说明：waitpid()会暂时停止目前进程的执行, 直到有信号来到或子进程结束.
     * 如果在调用wait()时子进程已经结束, 则wait()会立即返回子进程结束状态值.
     * 子进程的结束状态值会由参数status 返回, 而子进程的进程识别码也会一快返回.
     * 参数pid=-1 等待任何子进程, 相当于wait().
     * 参数WNOHANG：如果没有任何已经结束的子进程则马上返回, 不予以等待.
     * waitpid返回终止子进程的进程ID。
     */
    pid = waitpid(-1, &ret, WNOHANG);
    if (pid < 0 && errno == EINTR)
      continue;

    if (pid <= 0)
      return;

    list_for_each_entry_safe(p, tmp, &processes, list) {
      if (p->pid < pid)
        continue;

      if (p->pid > pid)
        break;

      uloop_process_delete(p);
      p->cb(p, ret);
    }
  }
}

/**
 * 通过写入字符到管道唤醒信号
 */
static void uloop_signal_wake(void) {
  do {
    if (write(waker_pipe, "w", 1) < 0) {
      /**
       * EINTR错误的产生：当阻塞于某个慢系统调用的一个进程捕获某个信号且相应信号处理函数返回时，
       * 该系统调用可能返回一个EINTR错误。例如：在socket服务器端，设置了信号捕获机制，
       * 有子进程，当在父进程阻塞于慢系统调用时由父进程捕获到了一个有效信号时，
       * 内核会致使accept返回一个EINTR错误(被中断的系统调用)。
       */
      if (errno == EINTR)
        continue;
    }
    fprintf(stderr, "uloop_signal_wake: running\n");
    break;
  } while (1);
}

/**
 * SIGINT (中断) 当用户按下时,通知前台进程组终止进程
 * 用户中断回调
 */
static void uloop_handle_sigint(int signo) {
  fprintf(stderr, "uloop_handle_sigint: signo：%d\n", signo);
  uloop_status = signo;
  uloop_cancelled = true;
  uloop_signal_wake();
}

/**
 * 子进程结束后回调（SIGCHLD (子进程结束) 当子进程终止时通知父进程）
 * 当主进程接到信号后，会先进入信号的回调函数进行处理
 */
static void uloop_sigchld(int signo) {
  fprintf(stderr, "uloop_sigchld: running\n");
  do_sigchld = true;
  uloop_signal_wake();
}

/**
 * 信号回调注册
 */
static void uloop_install_handler(int signum, void (*handler)(int),
                                  struct sigaction *old, bool add) {
  struct sigaction s;
  struct sigaction *act;

  act = NULL;
  /**
   * sigaction是一个函数，可以用来查询或设置信号处理方式。
   *
   第二个参数为新的action的地址，第三个参数为被替换的旧action，如果不想保存（使用）旧的action，就设为NULL
   */
  sigaction(signum, NULL, &s);

  /* 如果是新增处理函数的操作 */
  if (add) {
    /**
     * SIG_DFL：默认信号处理程序
     * 如果参数signum所指的信号的处理方法为默认值
     * 不重写已存在的自定义处理
     */
    if (s.sa_handler == SIG_DFL) {
      /*
        void * memcpy ( void * dest, const void * src, size_t num );
        memcpy() 会复制 src 所指的内存内容的前 num 个字节到
        dest所指的内存地址上。
      */
      memcpy(old, &s, sizeof(struct sigaction));
      s.sa_handler = handler;
      s.sa_flags = 0;
      act = &s;
    }
  } else if (s.sa_handler ==
             handler) { /* Do not restore if someone modified our handler */
    act = old;
  }

  if (act != NULL)
    sigaction(signum, act, NULL);
}

static void uloop_ignore_signal(int signum, bool ignore) {
  struct sigaction s;
  void *new_handler = NULL;

  sigaction(signum, NULL, &s);

  if (ignore) {
    if (s.sa_handler == SIG_DFL) /* 如果没有自定义函数设置，则可忽略 */
      new_handler = SIG_IGN;
  } else {
    if (s.sa_handler ==
        SIG_IGN) /* Restore only if noone modified our SIG_IGN */
      new_handler = SIG_DFL;
  }

  if (new_handler) {
    s.sa_handler = new_handler;
    s.sa_flags = 0;
    sigaction(signum, &s, NULL);
  }
}

/**
 * 信号处理设置
 * 信号机制是进程之间相互传递消息的一种方法，信号全称为软中断信号，也有人称作软中断
 */
static void uloop_setup_signals(bool add) {
  static struct sigaction old_sigint, old_sigchld, old_sigterm;

  /* SIGINT (中断) 当用户按下时,通知前台进程组终止进程 */
  uloop_install_handler(SIGINT, uloop_handle_sigint, &old_sigint, add);
  /* SIGTERM (软中断) 使用不带参数的kill命令时终止进程 */
  uloop_install_handler(SIGTERM, uloop_handle_sigint, &old_sigterm, add);
  /* SIGCHLD (子进程结束) 当子进程终止时通知父进程 */
  uloop_install_handler(SIGCHLD, uloop_sigchld, &old_sigchld, add);
  /* SIGPIPE
   * 写至无读进程的管道,或者Socket通信SOCT_STREAM的读进程已经终止，而再写入 */
  uloop_ignore_signal(SIGPIPE, add);
}

/**
 * 获取下一个超时设置
 */
static int uloop_get_next_timeout(struct timeval *tv) {
  struct uloop_timeout *timeout;
  int diff;

  if (list_empty(&timeouts))
    return -1;

  timeout = list_first_entry(&timeouts, struct uloop_timeout, list);
  diff = tv_diff(&timeout->time, tv);
  if (diff < 0)
    return 0;

  return diff;
}

static void uloop_process_timeouts(struct timeval *tv) {
  struct uloop_timeout *t;

  while (!list_empty(&timeouts)) {
    t = list_first_entry(&timeouts, struct uloop_timeout, list);

    if (tv_diff(&t->time, tv) > 0)
      break;

    uloop_timeout_cancel(t);
    if (t->cb)
      t->cb(t);
  }
}

static void uloop_clear_timeouts(void) {
  struct uloop_timeout *t, *tmp;

  list_for_each_entry_safe(t, tmp, &timeouts, list) uloop_timeout_cancel(t);
}

static void uloop_clear_processes(void) {
  struct uloop_process *p, *tmp;

  list_for_each_entry_safe(p, tmp, &processes, list) uloop_process_delete(p);
}

bool uloop_cancelling(void) { return uloop_run_depth > 0 && uloop_cancelled; }

/**
 * 事件循环主处理入口
 * 1.当某一个进程第一次调用uloop_run时，注册sigchld和sigint信号
 * 2.循环获取当前时间，把超时的timeout处理掉，有一条timeout链表在维护
 * 3.循环检测是否收到一个sigchld信号，如果收到，删除对应的子进程，有一条process子进程链表在维护
 * 4.循环调用epoll_wait监听相应的触发事件文件描述符fd
 */
int uloop_run(void) {
  struct timeval tv;

  /*
   * Handlers are only updated for the first call to uloop_run() (and restored
   * when this call is done).
   * 第一次运行uloop_run时调用, 注册信号处理函数
   */
  if (!uloop_run_depth++)
    uloop_setup_signals(true);

  uloop_status = 0;
  uloop_cancelled = false;

  /* 进入事件循环，单线程，默认LT模式 */
  while (!uloop_cancelled) {

    fprintf(stderr, "SRV: Begin uloop\n");

    //获取当前时间
    uloop_gettime(&tv);

    /**
     * 检查超时进程，超时则执行回调。
     * 如执行CGI脚本，则设置超时时间到全局变量timeouts中，
     * epoll_wait则会读取timeouts等待脚本执行。
     */
    uloop_process_timeouts(&tv);

    /**
     * SIGCHLD (子进程结束) 当子进程终止时通知父进程
     * 收到一个sigchld的信号
     */
    if (do_sigchld)
      uloop_handle_processes();

    if (uloop_cancelled)
      break;

    //获取当时间时间
    uloop_gettime(&tv);

    /**
     * 处理相应的触发事件fd
     *
     * 如何区分每个超时设置是对应的处理？
     * 单线程，无法保证准确地处理超时进程，只有重新进入循环，进入uloop_process_timeouts后，
     * 才能确认是否已超时
     */
    uloop_run_events(uloop_get_next_timeout(&tv));
  }

  if (!--uloop_run_depth)
    uloop_setup_signals(false);

  return uloop_status;
}

/**
 * 销毁事件循环
 */
void uloop_done(void) {
  if (poll_fd >= 0) {
    close(poll_fd);
    poll_fd = -1;
  }

  if (waker_pipe >= 0) {
    uloop_fd_delete(&waker_fd);
    close(waker_pipe);
    close(waker_fd.fd);
    waker_pipe = -1;
  }

  uloop_clear_timeouts();
  uloop_clear_processes();
}
