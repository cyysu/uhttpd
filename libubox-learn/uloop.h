/*
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2013 Felix Fietkau <nbd@openwrt.org>
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
#ifndef _ULOOP_H__
#define _ULOOP_H__

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#define USE_KQUEUE
#else
#define USE_EPOLL
#endif

#include "list.h"

struct uloop_fd;
struct uloop_timeout;
struct uloop_process;

/* 描述符事件处理函数 */
typedef void (*uloop_fd_handler)(struct uloop_fd *u, unsigned int events);
/* 定时器事件处理函数 */
typedef void (*uloop_timeout_handler)(struct uloop_timeout *t);
/* 进程事件处理函数 */
typedef void (*uloop_process_handler)(struct uloop_process *c, int ret);

/* 事件标志 */
#define ULOOP_READ (1 << 0)
#define ULOOP_WRITE (1 << 1)
#define ULOOP_EDGE_TRIGGER (1 << 2)
#define ULOOP_BLOCKING (1 << 3)

#define ULOOP_EVENT_MASK (ULOOP_READ | ULOOP_WRITE)

/* internal flags */
#define ULOOP_EVENT_BUFFERED (1 << 4)
#ifdef USE_KQUEUE
#define ULOOP_EDGE_DEFER (1 << 5)
#endif

#define ULOOP_ERROR_CB (1 << 6)

/* 描述符结构体 */
struct uloop_fd {
  uloop_fd_handler cb; /** 描述符事件处理函数 */
  int fd;              /** 文件描述符，调用者初始化 */
  bool eof;
  bool error;
  bool registered; /** 是否已注册到uloop中 */
  uint8_t flags;
};

/* 超时处理结构体 */
struct uloop_timeout {
  struct list_head list;
  bool pending; /* 是否正在执行 */

  uloop_timeout_handler cb; /** 超时回调函数 */
  struct timeval time;      /** 结束时间 */
};

/* 进程结构体 */
struct uloop_process {
  struct list_head list;
  bool pending; /* 是否正在执行 */

  uloop_process_handler cb; /** 进程事件处理函数 */
  pid_t pid;                /** 进程号*/
};

extern bool uloop_cancelled;
extern bool uloop_handle_sigchld;

/**
 * 注册一个新描述符到事件处理循环
 */
int uloop_fd_add(struct uloop_fd *sock, unsigned int flags);
/**
* 从事件处理循环中销毁指定描述符
*/
int uloop_fd_delete(struct uloop_fd *sock);

/**
 * 注册一个新定时器
 */
int uloop_timeout_add(struct uloop_timeout *timeout);
/**
 * 设置定时器超时时间(毫秒)，并添加
 */
int uloop_timeout_set(struct uloop_timeout *timeout, int msecs);
/**
 * 销毁指定定时器
 */
int uloop_timeout_cancel(struct uloop_timeout *timeout);
/**
* 获取定时器还剩多长时间超时
*/
int uloop_timeout_remaining(struct uloop_timeout *timeout);

/**
 * 注册新进程到事件处理循环
 */
int uloop_process_add(struct uloop_process *p);
/**
* 从事件处理循环中销毁指定进程
*/
int uloop_process_delete(struct uloop_process *p);

bool uloop_cancelling(void);

static inline void uloop_end(void) { uloop_cancelled = true; }

int uloop_init(void);
int uloop_run(void);
void uloop_done(void);

#endif
