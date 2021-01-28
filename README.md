# CVE-2017-16995

记录一下自己折腾的CVE-2017-16995漏洞和相关分析

（希望能自己找个，笑

## 概述

此漏洞由于bpf虚拟执行时，校验器分支判断错误所引起的LPE

原理上是整数扩展漏洞

## 分析

触发	https://ph4ntonn.github.io/CVE-2017-16995-trigger.html

利用	https://ph4ntonn.github.io/CVE-2017-16995-exploit.html

结构	https://ph4ntonn.github.io/CVE-2017-16995-structure.html

## EXP

此处[下载](https://raw.githubusercontent.com/ph4ntonn/CVE-2017-16995/master/exp.c)，请自行编译