# Proxy-Lists🌐

这是一个定时更新的 proxy list，包含 HTTPS|SOCKS4|SOCKS5 节点。（HTTPS、SOCKS5全都支持SSL，SOCKS4不知道😅，反正基本都不行）

原理：

所有代理信息储存在 proxy.txt（`protocol://IP:port:country`），GitHub Action 定时执行，检查可用性，更新历史记录（`/data/history.json`），可用的储存于 `/pubulic/proxies.json`，再 deploy pages。

## 测试方式✅

HTTPS & SOCKS5 的代理，使用 `https://ifconfig.me/ip` `https://httpbin.org/ip` `https://api.ipify.org/?format=json` `https://api.i.pn/json`。

SOCKS4 代理，使用 `3.95.121.17/ip` `3.210.41.225/ip` `44.197.91.61/ip` `52.204.75.48/ip` `54.236.169.179/ip` `98.91.115.81/ip`。

## 贡献新代理✨

我们欢迎任何人贡献代理。**请使用 Issue 而不是 Pull requests**。

格式如下：

```plain
http://xxx.xxx.xxx.xxx:xxx:country
socks4://xxx.xxx.xxx.xxx:xxx:country
socks5://xxx.xxx.xxx.xxx:xxx:country
```

对于 HTTPS 与 SOCKS5 代理，**请确保支持 ssl（简单来说就是可以访问https网站😄）**。SOCKS4 不必确保。

## Stars⭐

[![Star History Chart](https://api.star-history.com/svg?repos=CB-X2-Jun/proxy-lists&type=date&legend=top-left)](https://www.star-history.com/#CB-X2-Jun/proxy-lists&type=date&legend=top-left)
