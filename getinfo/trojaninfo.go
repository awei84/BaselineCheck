package getinfo

import (
	"BaselineCheck/comm"
	"fmt"
	"os"
)

type SingleTrojanInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Action  string `json:"action"`
	Protect string `json:"protect"`
	Status  string `json:"status"`
	Score   int    `json:"score"`
	Type    string `json:"type"`
}


type ResTrojanInfo struct {
	TrojanInfo    []SingleTrojanInfo
}

func ReturnResultTro() (rtTro []SingleTrojanInfo) {
	var rt ResTrojanInfo
	var st SingleTrojanInfo
	GetTrojanInfo(&rt, st)
	rtTro = rt.TrojanInfo
	return 
}

func IsStatus(isExist string, stj *SingleTrojanInfo) {
	if isExist != "" {
		stj.Status = "0"
	} else {
		stj.Status = "1"
	}
}

// 木马信息检测
func GetTrojanInfo(resGet *ResTrojanInfo, stj SingleTrojanInfo) {
	stj.Action = "执行ps -ef检测系统中是否存在挖矿进程"
	stj.Protect = "执行ps -ef定位进程pid，然后找到挖矿运行程序查看运行逻辑进行有目录查杀以及全盘扫描检测"
	stj.Score = 10
	stj.Type = "挖矿木马"

	stj.Name = "检测是否存在xsdk挖矿木马"
	xsdk := comm.GetCmdRes(`ps aux | grep -Ei "mgo|xsdk" | grep -v 'grep'`)
	IsStatus(xsdk, &stj)
	stj.Path = xsdk
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在ssl3挖矿木马"
	ssl3 := comm.GetCmdRes(`ps -ef | grep -Ei "ssl\d.plist"`)
	IsStatus(ssl3, &stj)
	stj.Path = ssl3
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在xmrig挖矿木马"
	xmrig := comm.GetCmdRes(`ps aux | grep -Ei "xmrig" | grep -v 'grep'`)
	IsStatus(xmrig, &stj)
	stj.Path = xmrig
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在WatchDogsMiner挖矿木马"
	watchdogs := ""
	_, watchdogsErr := os.Stat(`/etc/init.d/watchdogs`)
	if watchdogsErr == nil || os.IsExist(watchdogsErr) {
		stj.Path = "/etc/init.d/watchdogs"
		watchdogs = "ok"
	}
	IsStatus(watchdogs, &stj)
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在DDG挖矿木马"
	ddg := ""
	_, ddgErr := os.Stat(`/var/spool/cron/crontabs/root`)
	if ddgErr == nil || os.IsExist(ddgErr) {
		stj.Path = "/var/spool/cron/crontabs/root"
		ddg = "ok"
	}
	IsStatus(ddg, &stj)
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在sustes挖矿木马"
	sustes := comm.GetCmdRes(`ps ax | grep 'wc.conf\|wq.conf\|wm.conf\|wt.conf' | grep -v grep | grep 'ppl\|pscf\|ppc\|ppp' | awk '{print $1}'`)
	IsStatus(sustes, &stj)
	stj.Path = sustes
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在Khugepageds挖矿木马"
	khugepageds := comm.GetCmdRes(`ps auxf | grep -v grep | grep mndzbcb | awk '{print $2}'`)
	IsStatus(khugepageds, &stj)
	stj.Path = khugepageds
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在PHP脚本Webshell后门"
	php := comm.GetCmdRes(`find / -name "*.php" -mtime 30 |xargs grep -E "phpspy|c99sh|milw0rm|eval(gunerpress|eval(base64_decoolcode|spider_bc))"`)
	IsStatus(php, &stj)
	stj.Path = php
	stj.Type = "网站后门"
	stj.Action = "检查网站目录下是否存在webshell文件及流量"
	stj.Protect = "删除webshell并进行全盘查杀"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在JSP脚本Webshell后门或者777权限JSP威胁脚本"
	jsp := comm.GetCmdRes(`find / -name "*.jsp" -perm 777`)
	IsStatus(jsp, &stj)
	stj.Path = jsp
	stj.Type = "网站后门"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测是否存在Base反弹shell后门"
	bash := comm.GetCmdRes(`ps -ef | grep 'bash -i' | grep -v 'grep'`)
	IsStatus(bash, &stj)
	stj.Path = bash
	stj.Type = "网站后门"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测crontab定时任务中是否存在可疑进程"
	crontab := comm.GetCmdRes(`crontab -l |grep -E "http|curl" |grep -E "http|wget|ftp"`)
	IsStatus(crontab, &stj)
	stj.Path = crontab
	stj.Type = "可疑进程"
	stj.Score = 3
	stj.Action = "执行crontal -l检测系统中是否存在挖矿进程"
	stj.Protect = "执行crontal -l查看定时任务下异常进程，然后定位脚本进程"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测history中是否存在可疑历史执行命令进程"
	// history是bash内置命令,bin/bash无法开启,所以需要先打开bash的history配置
	history := comm.GetCmdRes(`HISTFILE=~/.bash_history && set -o history && history |grep -E "http|curl" |grep -E "http|wget" |grep -Ev "crontab|history|git"`)
	IsStatus(history, &stj)
	stj.Path = history
	stj.Type = "可疑进程"
	stj.Score = 3
	stj.Action = "执行history检测系统中是否存在挖矿进程"
	stj.Protect = "执行history命令查看异常历史命令，然后配合查看last和日志等确认攻击入侵方式进行定位"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)

	stj.Name = "检测ps进程中是否存在可疑运行进程"
	ps := comm.GetCmdRes(`ps -ef | grep -v grep |grep -E 'http|curl' |grep -E 'http|wget' | grep -v baseline_linux`)
	IsStatus(ps, &stj)
	stj.Path = ps
	stj.Type = "可疑进程"
	stj.Score = 3
	stj.Action = "执行ps -ef检测系统中是否存在挖矿进程"
	stj.Protect = "执行ps -ef命令查看异常进程，然后配合查看last和日志等确认攻击入侵方式进行定位"
	resGet.TrojanInfo = append(resGet.TrojanInfo, stj)
	fmt.Println("[2/4] Baseline trojanInfo data check finished!")

}