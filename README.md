# boyika/博伊卡

安全 快速 可控的本地DNS服务器

## 功能

- 替代本地HOSTS文件，支持模糊匹配
- 拦截特定域名，如 ad.test.com, *.ad.com
- 阻止解析结果中特定的IP的访问
- 为特定域名指定转发服务器、通过DOH（DNS Over HTTPS）
- 缓存查询结果，加快访问速度

### 配置说明

离线版本的数据文件为JSON格式，下面是一个完整示例。

`hosts` ：HOSTS 的配置，指定 `aaa.com` 的解析结果为 `3.3.3.3`， 泛域名 `*.bbb.com` 的解析结果为 `2.2.2.2`,可按此配置添加多个HOSTS内容。

`block_name` ：阻止列表中的域名解析，示例中a1.com，和*.a2.com将被拦截

`block_ip` ：阻止解析结果包含列表IP的请求

`forward` ：转发配置，默认由8.8.8.8,1,2,4,8两组DNS负责解析,google.com由1.1.1.1负责解析

`doh` ：DNS Over HTTP 的配置，www.163.com 将会由cloudflare、google两组支持DOH 的DNS来负责解析
```
{
	"hosts": [
		{
			"pattern": "aaa.com",
			"data": "3.3.3.3"
		},
		{
			"pattern": "*.bbb.com",
			"data": "2.2.2.2"
		}
	],
	"block_name": [
		"a1.com",
		"*.a2.com"
	],
	"block_ip": [
		"1.1.1.1",
		"2.2.*"
	],
	"forward": [
		{
			"name": [
				"8.8.8.8:53",
				"1.2.4.8:53"
			],
			"domain": [
				"*.*"
			]
		},
		{
			"name": [
				"1.1.1.1:53"
			],
			"domain": [
				"google.com"
			]
		}
	],
	"doh": [
		{
			"name": [
				"https://cloudflare-dns.com/dns-query?name={name}\u0026type={type}",
				"https://dns.google.com/reslove?name={name}\u0026type={type}\u0026dnssec=true\u0026ecs=113.246.106.143%2F24"
			],
			"domain": [
				"www.163.com"
			]
		}
	]
}
```

