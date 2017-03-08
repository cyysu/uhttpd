/*
 * 双向链表
 * https://www.ibm.com/developerworks/cn/linux/kernel/l-chain/
 * Copyright (c) 2011 Felix Fietkau <nbd@openwrt.org>
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _LINUX_LIST_H_
#define _LINUX_LIST_H_

#include <stdbool.h>
#include <stddef.h>

#define prefetch(x)

// container_of宏用来根据成员的地址来获取结构体的地址
#ifndef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)NULL)->member) *__mptr = (ptr);                      \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
#endif

//双向链表
struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

/*
  struct list_head foo = { &(foo) , &(foo)}
  在本文中等价于：
  struct list_head {struct list_head *next, *prev; } foo = { &(foo) , &(foo)};
  按照成员的对应赋值就是：
  struct list_head foo; foo.next = &foo; foo.prev = &foo;
  总而言之：用同一个对象初始化next 和 prev
*/
#define LIST_HEAD_INIT(name)                                                   \
  { &(name), &(name) }
#undef LIST_HEAD
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

/*
  初始化一个结点名字为name的双向循环链表的头结点
  LIST_HEAD_INIT is a static initializer, INIT_LIST_HEAD is a function. They
  both initialise a list_head to be empty.
  If you are statically declaring a list_head, you should use LIST_HEAD_INIT,
  eg:
  static struct list_head mylist = LIST_HEAD_INIT(mylist);
  You should use INIT_LIST_HEAD() for a list head that is dynamically allocated,
  usually part of another structure. There are many examples in the kernel
  source.
*/
static inline void INIT_LIST_HEAD(struct list_head *list) {
  list->next = list->prev = list;
}

//测试链表是否为空
static inline bool list_empty(const struct list_head *head) {
  return (head->next == head);
}

//是否等于当前节点的上一节点
static inline bool list_is_first(const struct list_head *list,
                                 const struct list_head *head) {
  return list->prev == head;
}

//是否等于当前节点的下一节点
static inline bool list_is_last(const struct list_head *list,
                                const struct list_head *head) {
  return list->next == head;
}

//删除结点。删除链表中prev与next之间的元素
static inline void _list_del(struct list_head *entry) {
  entry->next->prev = entry->prev;
  entry->prev->next = entry->next;
}

/**
 * 把指定节点从链表中删除
 */
static inline void list_del(struct list_head *entry) {
  _list_del(entry);
  entry->next = entry->prev = NULL;
}

//插入新条目,插在prev与next中间
static inline void _list_add(struct list_head *_new, struct list_head *prev,
                             struct list_head *next) {
  next->prev = _new;
  _new->next = next;
  _new->prev = prev;
  prev->next = _new;
}

/**
 * 把指定节点从链表中删除，并初始此节点
 */
static inline void list_del_init(struct list_head *entry) {
  _list_del(entry);
  INIT_LIST_HEAD(entry);
}

/**
 * 从一个结构的成员指针找到其容器的指针
 *
 * ptr是指向该数据中list_head成员的指针，
 * 也就是存储在链表中的地址值，type是数据项的类型，
 * field则是数据项类型定义中list_head成员的变量名
 */
#define list_entry(ptr, type, field) container_of(ptr, type, field)
/**
 * 已知type类型的结构体中field成员的指针后，
 * 求得它所在的链表的下一个指针所指的field所在的type类型的结构体（容器）的起始地址！
 */
#define list_first_entry(ptr, type, field) list_entry((ptr)->next, type, field)
/**
 * 已知type类型的结构体中field成员的指针后，
 * 求得它所在的链表的上一个指针所指的field所在的type类型的结构体（容器）的的起始地址！
 */
#define list_last_entry(ptr, type, field) list_entry((ptr)->prev, type, field)
// 从head节点开始（不包括head节点！）遍历它的每一个节点！
#define list_for_each(p, head) for (p = (head)->next; p != (head); p = p->next)
/**
 * 从head节点开始（不包括head节点！）遍历它的每一个节点！
 * 它用n先将下一个要遍历的节点保存起来，防止删除本节点后，无法找到下一个节点，而出现错误！
 */
#define list_for_each_safe(p, n, head)                                         \
  for (p = (head)->next, n = p->next; p != (head); p = n, n = p->next)
/**
 * 已知指向某个结构体的指针pos，以及指向它中field成员的指针head，
 * 从下一个结构体开始向后遍历这个结构体链
 */
#define list_for_each_entry(p, h, field)                                       \
  for (p = list_first_entry(h, typeof(*p), field); &p->field != (h);           \
       p = list_entry(p->field.next, typeof(*p), field))
/**
 * 先保存下一个要遍历的节点！从head下一个节点向后遍历链表。
 */
#define list_for_each_entry_safe(p, n, h, field)                               \
  for (p = list_first_entry(h, typeof(*p), field),                             \
      n = list_entry(p->field.next, typeof(*p), field);                        \
       &p->field != (h);                                                       \
       p = n, n = list_entry(n->field.next, typeof(*n), field))
/**
 * 同list_for_each_entry，方向相反
 */
#define list_for_each_entry_reverse(p, h, field)                               \
  for (p = list_last_entry(h, typeof(*p), field); &p->field != (h);            \
       p = list_entry(p->field.prev, typeof(*p), field))
/**
 * 同list_for_each，方向相反
 */
#define list_for_each_prev(p, h) for (p = (h)->prev; p != (h); p = p->prev)
/**
 * 同list_for_each_safe，方向相反
 */
#define list_for_each_prev_safe(p, n, h)                                       \
  for (p = (h)->prev, n = p->prev; p != (h); p = n, n = p->prev)

/**
 * 头插法，调用_list_add()实现
 * 在表头插入是插入在head之后
 */
static inline void list_add(struct list_head *_new, struct list_head *head) {
  _list_add(_new, head, head->next);
}

/**
 * 尾部插法
 * 在表尾插入是插入在head->prev之后
 */
static inline void list_add_tail(struct list_head *_new,
                                 struct list_head *head) {
  _list_add(_new, head->prev, head);
}

//将该结点摘除并插入到链表头部
static inline void list_move(struct list_head *list, struct list_head *head) {
  _list_del(list);
  list_add(list, head);
}

//将该结点摘除并插入到链表尾部
static inline void list_move_tail(struct list_head *entry,
                                  struct list_head *head) {
  _list_del(entry);
  list_add_tail(entry, head);
}

//合并链表， 将链表list与head合并
static inline void _list_splice(const struct list_head *list,
                                struct list_head *prev,
                                struct list_head *next) {
  struct list_head *first;
  struct list_head *last;

  if (list_empty(list))
    return;

  first = list->next;
  last = list->prev;
  first->prev = prev;
  prev->next = first;
  last->next = next;
  next->prev = last;
}

/**
 * 将新list连接到head的next中
 */
static inline void list_splice(const struct list_head *list,
                               struct list_head *head) {
  _list_splice(list, head, head->next);
}

/**
 * 将新list连接到head的prev中
 */
static inline void list_splice_tail(struct list_head *list,
                                    struct list_head *head) {
  _list_splice(list, head->prev, head);
}

/**
 * 将新list连接到head的next中
 * 将两链表合并后，重新初始化list（为了避免引起混乱）
 */
static inline void list_splice_init(struct list_head *list,
                                    struct list_head *head) {
  _list_splice(list, head, head->next);
  INIT_LIST_HEAD(list);
}

/**
 * 将新list连接到head的prev中
 * 将两链表合并后，重新初始化list（为了避免引起混乱）
 */
static inline void list_splice_tail_init(struct list_head *list,
                                         struct list_head *head) {
  _list_splice(list, head->prev, head);
  INIT_LIST_HEAD(list);
}

#endif /* _LINUX_LIST_H_ */
