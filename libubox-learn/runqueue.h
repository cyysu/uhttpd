/*
 * runqueue.c - a simple task queueing/completion tracking helper
 *
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
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

#ifndef __LIBUBOX_RUNQUEUE_H
#define __LIBUBOX_RUNQUEUE_H

#include "list.h"
#include "safe_list.h"
#include "uloop.h"

struct runqueue;
struct runqueue_task;
struct runqueue_task_type;

/* 任务队列结构体 */
struct runqueue {
  struct safe_list tasks_active;   /** 活动任务队列 */
  struct safe_list tasks_inactive; /** 不活动任务队列 */
  struct uloop_timeout timeout;

  int running_tasks;     /** 当前活动任务数目 */
  int max_running_tasks; /** 允许最大活动任务数目 */
  bool stopped;          /** 是否停止任务队列 */
  bool empty; /** 任务队列(包括活动和不活动)是否为空 */

  /* called when the runqueue is emptied */
  void (*empty_cb)(struct runqueue *q);
};

/* 任务处理函数 */
struct runqueue_task_type {
  const char *name;

  /*
   * called when a task is requested to run
   *
   * The task is removed from the list before this callback is run. It
   * can re-arm itself using runqueue_task_add.
   */
  void (*run)(struct runqueue *q, struct runqueue_task *t);

  /*
   * called to request cancelling a task
   *
   * int type is used as an optional hint for the method to be used when
   * cancelling the task, e.g. a signal number for processes. Calls
   * runqueue_task_complete when done.
   */
  void (*cancel)(struct runqueue *q, struct runqueue_task *t, int type);

  /*
   * called to kill a task. must not make any calls to runqueue_task_complete,
   * it has already been removed from the list.
   */
  void (*kill)(struct runqueue *q, struct runqueue_task *t);
};

/* 任务结构体 */
struct runqueue_task {
  struct safe_list list;
  const struct runqueue_task_type *type;
  struct runqueue *q;

  void (*complete)(struct runqueue *q, struct runqueue_task *t);

  struct uloop_timeout timeout;
  int run_timeout; /** >0表示规定此任务执行只有run_timeout毫秒 */
  int cancel_timeout; /** >0表示规则任务延取消操作执行只有run_timeout毫秒*/
  int cancel_type;

  bool queued;    /** 此任务是否已加入任务队列中 */
  bool running;   /** 此任务是否活动，即已在活动队列中 */
  bool cancelled; /** 此任务是否已被取消 */
};

/* 进程任务结构体 */
struct runqueue_process {
  struct runqueue_task task;
  struct uloop_process proc;
};

#define RUNQUEUE_INIT(_name, _max_running)                                     \
  {                                                                            \
    .tasks_active = SAFE_LIST_INIT(_name.tasks_active),                        \
    .tasks_inactive = SAFE_LIST_INIT(_name.tasks_inactive),                    \
    .max_running_tasks = _max_running                                          \
  }

#define RUNQUEUE(_name, _max_running)                                          \
  struct runqueue _name = RUNQUEUE_INIT(_name, _max_running)

/**
 * 初始化任务队列
 */
void runqueue_init(struct runqueue *q);
/**
 * 取消所有任务队列
 */
void runqueue_cancel(struct runqueue *q);
/**
* 取消活动中的任务
*/
void runqueue_cancel_active(struct runqueue *q);
/**
 * 取消不活动的任务
 */
void runqueue_cancel_pending(struct runqueue *q);
/**
 * 杀死所有任务
 */
void runqueue_kill(struct runqueue *q);
/**
 * 停止所有任务
 */
void runqueue_stop(struct runqueue *q);
/**
* 重新开始任务
*/
void runqueue_resume(struct runqueue *q);
/**
 * 添加新任务到队列尾
 *
 * @running true-加入活动队列；false-加入不活动队列
 */
void runqueue_task_add(struct runqueue *q, struct runqueue_task *t,
                       bool running);
/**
 * 添加新任务到队列头
 *
 * @running true-加入活动队列；false-加入不活动队列
 */
void runqueue_task_add_first(struct runqueue *q, struct runqueue_task *t,
                             bool running);
/**
 * 完全任务
 */
void runqueue_task_complete(struct runqueue_task *t);
/**
* 取消任务
*/
void runqueue_task_cancel(struct runqueue_task *t, int type);
/**
* 杀死任务
*/
void runqueue_task_kill(struct runqueue_task *t);
/* 进程任务操作函数 */
void runqueue_process_add(struct runqueue *q, struct runqueue_process *p,
                          pid_t pid);

/* to be used only from runqueue_process callbacks */
void runqueue_process_cancel_cb(struct runqueue *q, struct runqueue_task *t,
                                int type);
void runqueue_process_kill_cb(struct runqueue *q, struct runqueue_task *t);

#endif
