# uHTTPd
uHTTPd 是一个 OpenWrt/LUCI 开发者从头编写的 Web 服务器。 它着力于实现一个稳定高效的服务器，能够满足嵌入式设备的轻量级任务需求，且能够与 OpenWrt 的配置框架 (UCI) 整合。默认情况下它被用于 OpenWrt 的 Web 管理接口 LuCI。当然，uHTTPd 也能提供一个常规 Web 服务器所需要的所有功能。

# 编译
Uhttp的编译时cmake编译系统，按照cmake编译方法编译即可。Uhttp是基于ubox ubus json-c的，如果加上SSL ，还需要openssl库。
```
$ git clone https://github.com/json-c/json-c.git
$ cd json-c
$ ./autogen.sh --configure
$ make
$ make install
```

```
$ git clone git://git.openwrt.org/project/libubox.git
$ cd libubox
$ cmake -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_LUA=off
$ make
$ make install
```

```
$ git clone git://git.openwrt.org/project/ubus.git
$ cd ubus
$ cmake -DBUILD_LUA=off
$ make
$ make install
```
最后编译安装uhttpd。（注意：CMakeLIsts.txt中的编译新增了-Werror选项，所有警告会当成错误进行处理）
```
$ cd uhttpd/build
$ cmake ..
$ make
$ make install
```

# 配置项
```
Usage: ./uhttpd -p [addr:]port [-h docroot]
        -f              Do not fork to background
        -c file         Configuration file, default is '/etc/httpd.conf'
        -p [addr:]port  Bind to specified address and port, multiple allowed
        -s [addr:]port  Like -p but provide HTTPS on this port
        -C file         ASN.1 server certificate file
        -K file         ASN.1 server private key file
        -h directory    Specify the document root, default is '.'
        -E string       Use given virtual URL as 404 error handler
        -I string       Use given filename as index for directories, multiple allowed
        -S              Do not follow symbolic links outside of the docroot
        -D              Do not allow directory listings, send 403 instead
        -R              Enable RFC1918 filter
        -n count        Maximum allowed number of concurrent requests
        -l string       URL prefix for Lua handler, default is '/lua'
        -L file         Lua handler script, omit to disable Lua
        -u string       URL prefix for HTTP/JSON handler
        -U file         Override ubus socket path
        -x string       URL prefix for CGI handler, default is '/cgi-bin'
        -i .ext=path    Use interpreter at path for files with the given extension
        -t seconds      CGI, Lua and UBUS script timeout in seconds, default is 60
        -T seconds      Network timeout in seconds, default is 30
        -d string       URL decode given string
        -r string       Specify basic auth realm
        -m string       MD5 crypt given string
```

# 简要流程
<!--
```flow
st=>start: uhttpd
e=>end
option=>operation: 配置参数配置
wait=>operation: 等待请求
accept=>operation: 接受请求
resolve=>operation: 解析请求
dispatch=>operation: 分发请求
static=>operation: 静态文件
cgi=>operation: CGI请求
lua=>operation: LUA请求
response=>operation: 响应请求
new_read=>condition: 是否新连接？
script_static=>condition: 是否静态文件？
lua_cgi=>condition: 是否为lua？

st->option->wait->new_read
new_read(no)->accept->resolve->script_static
new_read(yes, right)->wait
script_static(yes)->static->response
script_static(no)->lua_cgi
lua_cgi(yes)->lua->response
lua_cgi(no)->cgi->response
response->e
```
-->
![简要流程](http://static.zgjian.cc/post/58db41ddbb29d.png)

# 更多详情
[uHTTPd [OpenWrt Wiki]](https://wiki.openwrt.org/zh-cn/doc/howto/http.uhttpd)