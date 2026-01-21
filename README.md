# Proxy-Lists

这是一个定时更新的 proxy list，包含 HTTPS|SOCKS4|SOCKS5 节点。（全都支持SSL）

原理：

所有代理信息储存在 proxy.txt（`protocol://IP:port:country`），GitHub Action 定时执行，检查可用性，更新历史记录（`/data/history.json`），可用的储存于 `/pubulic/proxies.json`，再 deploy pages。

我们欢迎任何人贡献代理。**请使用 Issue 而不是 Pull requests**。

格式如下：

```plain
http://xxx.xxx.xxx.xxx:xxx:country
socks4://xxx.xxx.xxx.xxx:xxx:country
socks5://xxx.xxx.xxx.xxx:xxx:country
```

**请确保支持 ssl（简单来说就是可以访问https网站😄）**
