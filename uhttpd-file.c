/*
 * uhttpd - Tiny single-threaded httpd - Static file handler
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

#include "uhttpd-file.h"

#include "uhttpd-mimetypes.h"

#ifdef __APPLE__
time_t timegm(struct tm *tm);
#endif

/**
 * 返回文件扩展名
 */
static const char *uh_file_mime_lookup(const char *path) {
  struct mimetype *m = &uh_mime_types[0];
  const char *e;

  while (m->extn) {
    e = &path[strlen(path) - 1];

    while (e >= path) {
      if ((*e == '.' || *e == '/') && !strcasecmp(&e[1], m->extn))
        return m->mime;

      e--;
    }

    m++;
  }

  return "application/octet-stream";
}

/**
 * 生成文件的实体值（ETags）
 * st_ino：节点号 st_mode：文件类型和文件访问权限被编码在该字段中
 * st_mtime：文件最后被修改时间
 */
static const char *uh_file_mktag(struct stat *s) {
  static char tag[128];

  snprintf(tag, sizeof(tag), "\"%x-%x-%x\"", (unsigned int)s->st_ino,
           (unsigned int)s->st_size, (unsigned int)s->st_mtime);

  return tag;
}

static time_t uh_file_date2unix(const char *date) {
  struct tm t;

  memset(&t, 0, sizeof(t));

  if (strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
    return timegm(&t);

  return 0;
}

static char *uh_file_unix2date(time_t ts) {
  static char str[128];
  struct tm *t = gmtime(&ts);

  strftime(str, sizeof(str), "%a, %d %b %Y %H:%M:%S GMT", t);

  return str;
}

/**
 * 查找某个首部的健值
 */
static char *uh_file_header_lookup(struct client *cl, const char *name) {
  int i;

  foreach_header(i, cl->request.headers) {
    if (!strcasecmp(cl->request.headers[i], name))
      return cl->request.headers[i + 1];
  }

  return NULL;
}

static int uh_file_response_ok_hdrs(struct client *cl, struct stat *s) {
  ensure_ret(uh_http_sendf(cl, NULL, "Connection: close\r\n"));

  if (s) {
    ensure_ret(uh_http_sendf(cl, NULL, "ETag: %s\r\n", uh_file_mktag(s)));
    ensure_ret(uh_http_sendf(cl, NULL, "Last-Modified: %s\r\n",
                             uh_file_unix2date(s->st_mtime)));
  }

  return uh_http_sendf(cl, NULL, "Date: %s\r\n", uh_file_unix2date(time(NULL)));
}

static int uh_file_response_200(struct client *cl, struct stat *s) {
  ensure_ret(uh_http_sendf(cl, NULL, "%s 200 OK\r\n",
                           http_versions[cl->request.version]));

  return uh_file_response_ok_hdrs(cl, s);
}

static int uh_file_response_304(struct client *cl, struct stat *s) {
  ensure_ret(uh_http_sendf(cl, NULL, "%s 304 Not Modified\r\n",
                           http_versions[cl->request.version]));

  return uh_file_response_ok_hdrs(cl, s);
}

static int uh_file_response_412(struct client *cl) {
  return uh_http_sendf(cl, NULL, "%s 412 Precondition Failed\r\n"
                                 "Connection: close\r\n",
                       http_versions[cl->request.version]);
}

/**
 * If-Match
 * 仅当客户端提供的实体与服务器上对应的实体相匹配时，才进行对应的操作。
 * 主要作用时，用作像 PUT
 * 这样的方法中，仅当从用户上次更新某个资源以来，该资源未被修改的情况下，才更新该资源。
 */
static int uh_file_if_match(struct client *cl, struct stat *s, int *ok) {
  const char *tag = uh_file_mktag(s);
  char *hdr = uh_file_header_lookup(cl, "If-Match");
  char *p;
  int i;

  if (hdr) {
    p = &hdr[0];

    for (i = 0; i < strlen(hdr); i++) {
      if ((hdr[i] == ' ') || (hdr[i] == ',')) {
        hdr[i++] = 0;
        p = &hdr[i];
      } else if (!strcmp(p, "*") || !strcmp(p, tag)) {
        *ok = 1;
        return *ok;
      }
    }

    *ok = 0;
    ensure_ret(uh_file_response_412(cl));
    return *ok;
  }

  *ok = 1;
  return *ok;
}

/**
 * If-Modified-Since是标准的HTTP请求头标签，在发送HTTP请求时，把浏览器端缓存页面的最后修改时间一起发到服务器去，服务器会把这个时间与服务器上实际文件的最后修改时间进行比较。
 * 如果时间一致，那么返回HTTP状态码304（不返回文件内容），客户端接到之后，就直接把本地缓存文件显示到浏览器中。
 * 如果时间不一致，就返回HTTP状态码200和新的文件内容，客户端接到之后，会丢弃旧文件，把新文件缓存起来，并显示到浏览器中。
 */
static int uh_file_if_modified_since(struct client *cl, struct stat *s,
                                     int *ok) {
  char *hdr = uh_file_header_lookup(cl, "If-Modified-Since");
  *ok = 1;

  if (hdr) {
    if (uh_file_date2unix(hdr) >= s->st_mtime) {
      *ok = 0;
      ensure_ret(uh_file_response_304(cl, s));
    }
  }

  return *ok;
}

/**
 * If-None-Match，它和ETags(HTTP协议规格说明定义ETag为“被请求变量的实体值”，
 * 或者是一个可以与Web资源关联的记号)常用来判断当前请求资源是否改变。
 * ETags和If-None-Match的工作原理是在HTTP Response中添加ETags信息。
 * 当客户端再次请求该资源时，将在HTTP
 * Request中加入If-None-Match信息（ETags的值）。
 * 如果服务器验证资源的ETags没有改变（该资源没有改变），将返回一个304状态；
 * 否则，服务器将返回200状态，并返回该资源和新的ETags。
 */
static int uh_file_if_none_match(struct client *cl, struct stat *s, int *ok) {
  const char *tag = uh_file_mktag(s);
  char *hdr = uh_file_header_lookup(cl, "If-None-Match");
  char *p;
  int i;
  *ok = 1;

  if (hdr) {
    p = &hdr[0];

    for (i = 0; i < strlen(hdr); i++) {
      if ((hdr[i] == ' ') || (hdr[i] == ',')) {
        hdr[i++] = 0;
        p = &hdr[i];
      } else if (!strcmp(p, "*") || !strcmp(p, tag)) {
        *ok = 0;

        if ((cl->request.method == UH_HTTP_MSG_GET) ||
            (cl->request.method == UH_HTTP_MSG_HEAD)) {
          ensure_ret(uh_file_response_304(cl, s));
        } else {
          ensure_ret(uh_file_response_412(cl));
        }

        break;
      }
    }
  }

  return *ok;
}

/**
 * 不支持
 * If-Range	如果该实体未被修改过，
 * 则向我发送我所缺少的那一个或多个部分；否则，发送整个新的实体
 */
static int uh_file_if_range(struct client *cl, struct stat *s, int *ok) {
  char *hdr = uh_file_header_lookup(cl, "If-Range");
  *ok = 1;

  if (hdr) {
    *ok = 0;
    ensure_ret(uh_file_response_412(cl));
  }

  return *ok;
}

/**
 * If-Unmodified-Since
 * 仅当该实体自某个特定时间已来未被修改的情况下，才发送回应。
 */
static int uh_file_if_unmodified_since(struct client *cl, struct stat *s,
                                       int *ok) {
  char *hdr = uh_file_header_lookup(cl, "If-Unmodified-Since");
  *ok = 1;

  if (hdr) {
    if (uh_file_date2unix(hdr) <= s->st_mtime) {
      *ok = 0;
      ensure_ret(uh_file_response_412(cl));
    }
  }

  return *ok;
}

static int uh_file_scandir_filter_dir(const struct dirent *e) {
  return strcmp(e->d_name, ".") ? 1 : 0;
}

/**
 * 列出目录结构
 */
static void uh_file_dirlist(struct client *cl, struct path_info *pi) {
  int i;
  int count = 0;
  char filename[PATH_MAX];
  char *pathptr;
  struct dirent **files = NULL;
  struct stat s;

  ensure_out(uh_http_sendf(cl, &cl->request,
                           "<html><head><title>Index of %s</title></head>"
                           "<body><h1>Index of %s</h1><hr /><ol>",
                           pi->name, pi->name));

  if ((count = scandir(pi->phys, &files, uh_file_scandir_filter_dir,
                       alphasort)) > 0) {
    memset(filename, 0, sizeof(filename));
    memcpy(filename, pi->phys, sizeof(filename));
    pathptr = &filename[strlen(filename)];

    /* 先列出目录 */
    for (i = 0; i < count; i++) {
      // strncat()用于将n个字符追加到字符串的结尾
      // 组成完整路径
      strncat(filename, files[i]->d_name,
              sizeof(filename) - strlen(files[i]->d_name));

      // S_IXOTH 00001 其他用户具可执行权限上述的文件类型在 POSIX
      // 中定义了检查这些类型的宏定义
      // 权限检查
      if (!stat(filename, &s) && (s.st_mode & S_IFDIR) &&
          (s.st_mode & S_IXOTH)) {
        ensure_out(uh_http_sendf(
            cl, &cl->request, "<li><strong><a href='%s%s'>%s</a>/"
                              "</strong><br /><small>modified: %s"
                              "<br />directory - %.02f kbyte<br />"
                              "<br /></small></li>",
            pi->name, files[i]->d_name, files[i]->d_name,
            uh_file_unix2date(s.st_mtime), s.st_size / 1024.0));
      }

      *pathptr = 0;
    }

    /* 然后列出文件 */
    for (i = 0; i < count; i++) {
      strncat(filename, files[i]->d_name,
              sizeof(filename) - strlen(files[i]->d_name));

      // S_IROTH 00004 其他用户具可读取权限
      if (!stat(filename, &s) && !(s.st_mode & S_IFDIR) &&
          (s.st_mode & S_IROTH)) {
        ensure_out(
            uh_http_sendf(cl, &cl->request, "<li><strong><a href='%s%s'>%s</a>"
                                            "</strong><br /><small>modified: %s"
                                            "<br />%s - %.02f kbyte<br />"
                                            "<br /></small></li>",
                          pi->name, files[i]->d_name, files[i]->d_name,
                          uh_file_unix2date(s.st_mtime),
                          uh_file_mime_lookup(filename), s.st_size / 1024.0));
      }

      *pathptr = 0;
    }
  }

  ensure_out(uh_http_sendf(cl, &cl->request, "</ol><hr /></body></html>"));

  /**
  * 如果一个HTTP消息（请求消息或应答消息）的Transfer-Encoding消息头的值为chunked，
  * 那么，消息体由数量未定的块组成，并以最后一个大小为0的块为结束。
  */
  ensure_out(uh_http_sendf(cl, &cl->request, ""));

out:
  if (files) {
    //释放资源
    for (i = 0; i < count; i++)
      free(files[i]);

    free(files);
  }
}

/**
 * 响应普通文件或目录请求
 */
bool uh_file_request(struct client *cl, struct path_info *pi) {
  int rlen;
  int ok = 1;
  int fd = -1;
  char buf[UH_LIMIT_MSGHEAD];

  /* 如果请求的是一个文件 */
  if ((pi->stat.st_mode & S_IFREG) && ((fd = open(pi->phys, O_RDONLY)) > 0)) {
    // 验证首部缓存条件
    if (ok)
      ensure_out(uh_file_if_modified_since(cl, &pi->stat, &ok));
    if (ok)
      ensure_out(uh_file_if_match(cl, &pi->stat, &ok));
    if (ok)
      ensure_out(uh_file_if_range(cl, &pi->stat, &ok));
    if (ok)
      ensure_out(uh_file_if_unmodified_since(cl, &pi->stat, &ok));
    if (ok)
      ensure_out(uh_file_if_none_match(cl, &pi->stat, &ok));

    if (ok > 0) {
      /* write status */
      ensure_out(uh_file_response_200(cl, &pi->stat));

      //响应文件扩展名
      ensure_out(uh_http_sendf(cl, NULL, "Content-Type: %s\r\n",
                               uh_file_mime_lookup(pi->name)));

      //响应文件长度
      ensure_out(
          uh_http_sendf(cl, NULL, "Content-Length: %i\r\n", pi->stat.st_size));

      /* 如果HTTP为1.1版本，则使用分块传输 */
      if ((cl->request.version > UH_HTTP_VER_1_0) &&
          (cl->request.method != UH_HTTP_MSG_HEAD)) {
        ensure_out(
            uh_http_send(cl, NULL, "Transfer-Encoding: chunked\r\n", -1));
      }

      /* 结束响应首部 */
      ensure_out(uh_http_send(cl, NULL, "\r\n", -1));

      /* 如果不是HEAD方法，则响应BODY */
      if (cl->request.method != UH_HTTP_MSG_HEAD) {
        /* 输出文件数据 */
        while ((rlen = read(fd, buf, sizeof(buf))) > 0) {
          ensure_out(uh_http_send(cl, &cl->request, buf, rlen));
        }

        /**
         * 如果一个HTTP消息（请求消息或应答消息）的Transfer-Encoding消息头的值为chunked，
         * 那么，消息体由数量未定的块组成，并以最后一个大小为0的块为结束。
         */
        ensure_out(uh_http_send(cl, &cl->request, "", 0));
      }
    }

    /* one of the preconditions failed, terminate opened header and exit */
    else {
      ensure_out(uh_http_send(cl, NULL, "\r\n", -1));
    }
  }

  /* 如果请求的是目录而且设置可以列出目录列表 */
  else if ((pi->stat.st_mode & S_IFDIR) && !cl->server->conf->no_dirlists) {
    /* write status */
    ensure_out(uh_file_response_200(cl, NULL));

    if (cl->request.version > UH_HTTP_VER_1_0)
      ensure_out(uh_http_send(cl, NULL, "Transfer-Encoding: chunked\r\n", -1));

    ensure_out(uh_http_send(cl, NULL, "Content-Type: text/html\r\n\r\n", -1));

    /* content */
    uh_file_dirlist(cl, pi);
  }

  /* 403 */
  else {
    ensure_out(uh_http_sendhf(cl, 403, "Forbidden",
                              "Access to this resource is forbidden"));
  }

out:
  if (fd > -1)
    close(fd);

  return false;
}
