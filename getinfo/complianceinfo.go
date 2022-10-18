package getinfo

import (
	"BaselineCheck/comm"
	"fmt"
	"log"
	"regexp"
	"strconv"
)

type SingleComplianceInfo struct {
	Name     string      `json:"name"`
	Action   string      `json:"action"`
	Standard interface{} `json:"standard"`
	Actual   interface{} `json:"actual"`
	Protect  string      `json:"protect"`
	Status   string      `json:"status"`
	Score    int         `json:"score"`
	Type     string      `json:"type"`
}

type ResComplianceInfo struct {
	ComplianceInfo []SingleComplianceInfo
}

func ReturnResultCom() (crCom []SingleComplianceInfo) {
	var cr ResComplianceInfo
	var tc SingleComplianceInfo
	GetComplianceInfo(&cr, tc)
	crCom = cr.ComplianceInfo
	return
}

// 基线合规
func GetComplianceInfo(resGet *ResComplianceInfo, stc SingleComplianceInfo) {
	var numPattern = regexp.MustCompile(`^\d+$|^\d+[.]\d+$`).MatchString // 判断是否为数值
	min := comm.GetCmdRes(`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`)
	if numPattern(min) {
		min_, errMin := strconv.Atoi(min)
		if errMin != nil {
			log.Printf("err:%v", errMin)
		} else {
			if min_ < 8 {
				stc.Name = "检查口令最小长度是否合规"
				stc.Action = "查看/etc/login.defs中PASS_MIN_LEN配置值"
				stc.Standard = 8
				stc.Actual = min_
				stc.Protect = "在文件/etc/login.defs中设置PASS_MIN_LEN不小于标准值"
				stc.Status = "0"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			} else {
				stc.Name = "检查口令最小长度"
				stc.Action = "查看/etc/login.defs中PASS_MIN_LEN配置值"
				stc.Standard = 8
				stc.Actual = min_
				stc.Protect = "在文件/etc/login.defs中设置PASS_MIN_LEN不小于标准值"
				stc.Status = "1"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			}
		}
	} else {
		stc.Name = "检查口令最小长度"
		stc.Action = "查看/etc/login.defs中PASS_MIN_LEN配置值"
		stc.Standard = 8
		stc.Actual = "not found"
		stc.Protect = "在文件/etc/login.defs中设置PASS_MIN_LEN不小于标准值"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	max := comm.GetCmdRes(`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`)
	if numPattern(max) {
		max_, errMax := strconv.Atoi(max)
		if errMax != nil {
			log.Printf("err:%v", errMax)
		} else {
			if max_ > 90 {
				stc.Name = "检查是否设置口令生存周期"
				stc.Action = "查看/etc/login.defs中PASS_MAX_DAYS配置值"
				stc.Standard = 90
				stc.Actual = max_
				stc.Protect = "在文件/etc/login.defs中设置PASS_MAX_DAYS不大于标准值90天"
				stc.Status = "0"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			} else {
				stc.Name = "检查是否设置口令生存周期"
				stc.Action = "查看/etc/login.defs中PASS_MAX_DAYS配置值"
				stc.Standard = 90
				stc.Actual = max_
				stc.Protect = "在文件/etc/login.defs中设置PASS_MAX_DAYS不大于标准值90天"
				stc.Status = "1"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			}
		}
	} else {
		stc.Name = "检查是否设置口令生存周期"
		stc.Action = "查看/etc/login.defs中PASS_MAX_DAYS配置值"
		stc.Standard = 90
		stc.Actual = "not found"
		stc.Protect = "在文件/etc/login.defs中设置PASS_MAX_DAYS不大于标准值90天"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	empty := comm.GetCmdRes(`awk -F: 'length($2)==0 {print $1}' /etc/shadow`)
	if empty != "" {
		stc.Name = "检查是否存在空口令用户"
		stc.Action = "查看/etc/shadow中空口令用户"
		stc.Standard = "no"
		stc.Actual = empty
		stc.Protect = "在文件/etc/shadow中检查空口令用户进行删除或者配置强口令"
		stc.Status = "0"
		stc.Score = 10
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否存在空口令用户"
		stc.Action = "查看/etc/shadow中空口令用户"
		stc.Standard = "no"
		stc.Actual = ""
		stc.Protect = "在文件/etc/shadow中检查空口令用户进行删除或者配置强口令"
		stc.Status = "1"
		stc.Score = 10
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	more := comm.GetCmdRes(`cat /etc/shadow | grep -E 'uucp|nuucp|lp|adm|sync|shutdown|halt|news|operator|gopher' | awk -F: '{print $1}'`)
	if more != "" {
		stc.Name = "检查是否禁用多余用户"
		stc.Action = "查看/etc/shadow中存在多余用户"
		stc.Standard = "no"
		stc.Actual = more
		stc.Protect = "对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否禁用多余用户"
		stc.Action = "查看/etc/shadow中存在多余用户"
		stc.Standard = "no"
		stc.Actual = ""
		stc.Protect = "对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	super := comm.GetCmdRes(`grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'`)
	if len(super) > 4 {
		stc.Name = "检查是否存在除root以外高权限用户"
		stc.Action = "查看/etc/shadow中存在非root高权限用户"
		stc.Standard = "root"
		stc.Actual = super
		stc.Protect = "对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否存在除root以外高权限用户"
		stc.Action = "查看/etc/shadow中存在非root高权限用户"
		stc.Standard = "root"
		stc.Actual = super
		stc.Protect = "对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	group := comm.GetCmdRes(`cat /etc/group | wc -l`)
	if group != "" {
		stc.Name = "检查是否按组进行账号管理"
		stc.Action = "查看/etc/login.defs中PASS_WARN_AGE配置"
		stc.Standard = "yes"
		stc.Actual = "yes"
		stc.Protect = "创建新的用户组 #groupadd 组名 #usermod -g 组名 -d 用户目录 -m 用户名 把用户添加进入某个组(s)或参考usermod --help说明进行设置"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否按组进行账号管理"
		stc.Action = "查看/etc/login.defs中PASS_WARN_AGE配置"
		stc.Standard = "yes"
		stc.Actual = "no"
		stc.Protect = "创建新的用户组 #groupadd 组名 #usermod -g 组名 -d 用户目录 -m 用户名 把用户添加进入某个组(s)或参考usermod --help说明进行设置"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	test := comm.GetCmdRes(`cat /etc/passwd |grep test*`)
	if test != "" {
		stc.Name = "检查是否存在test等可能有隐性威胁的测试用户"
		stc.Action = "查看/etc/passwd中用户信息"
		stc.Standard = "no"
		stc.Actual = test
		stc.Protect = "删除或者加固可疑的用户权限以及口令配置"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否存在test等可能有隐性威胁的测试用户"
		stc.Action = "查看/etc/passwd中用户信息"
		stc.Standard = "no"
		stc.Actual = "no"
		stc.Protect = "删除或者加固可疑的用户权限以及口令配置"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	sec1 := comm.GetCmdRes(`cat /etc/pam.d/system-auth | grep ocredit | awk -F'ocredit=' '{print $2}' | awk '{print $1}'`)
	sec2 := comm.GetCmdRes(`cat /etc/pam.d/system-auth | grep dcredit | awk -F'dcredit=' '{print $2}' | awk '{print $1}'`)
	sec3 := comm.GetCmdRes(`cat /etc/pam.d/system-auth | grep minlen | awk -F'minlen=' '{print $2}' | awk '{print $1}'`)
	sec4 := comm.GetCmdRes(`cat /etc/pam.d/system-auth | grep retry | awk -F'retry=' '{print $2}' | awk '{print $1}'`)
	if sec1 != "" && sec2 != "" && sec3 != "" && sec4 != "" {
		stc.Name = "检查主机密码复杂度策略"
		stc.Action = "查看/etc/pam.d/system-auth中密码创建策略配置"
		stc.Standard = "存在包含数字、字母等字符且密码不低于8位，重试次数不大于3次"
		stc.Actual = fmt.Sprintf("ocredit=%s | dcredit=%s | minlen=%s | retry=%s", sec1, sec2, sec3, sec4)
		stc.Protect = "配置/etc/pam.d/system-auth至少定义用户密码中最少有1个数字、最少有4个小写字母、密码的最小长度为8位、重试次数大于等于3次等"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查主机密码复杂度策略"
		stc.Action = "查看/etc/pam.d/system-auth中密码创建策略配置"
		stc.Standard = "存在包含数字、字母等字符且密码不低于8位，重试次数不大于3次"
		stc.Actual = ""
		stc.Protect = "配置/etc/pam.d/system-auth至少定义用户密码中最少有1个数字、最少有4个小写字母、密码的最小长度为8位、重试次数大于等于3次等"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	umask := comm.GetCmdRes(`grep -i 'umask 027' /etc/profile`)
	if umask != "" {
		stc.Name = "检查是否设置文件与目录缺省权限"
		stc.Action = "查看文件/etc/profile中umask设置"
		stc.Standard = 027
		stc.Actual = umask
		stc.Protect = "在文件/etc/profile中设置umask 027或UMASK 027，如果文件中含有umask参数，则需要在最前面设置该参数"
		stc.Status = "1" // TODO:这边有点奇怪？仿照python直接抄过来的
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否设置文件与目录缺省权限"
		stc.Action = "查看文件/etc/profile中umask设置"
		stc.Standard = 027
		stc.Actual = umask
		stc.Protect = "在文件/etc/profile中设置umask 027或UMASK 027，如果文件中含有umask参数，则需要在最前面设置该参数"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	login := comm.GetCmdRes(`cat /etc/ssh/sshd_config | grep -i '^PermitRootLogin yes'`)
	if login != "" {
		stc.Name = "检查是否限制root用户远程登录"
		stc.Action = "查看文件/etc/ssh/sshd_config中PermitRootLogin配置"
		stc.Standard = "no"
		stc.Actual = "yes"
		stc.Protect = "修改/etc/ssh/sshd_config文件,配置PermitRootLogin no重启服务，/etc/init.d/sshd restart"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否限制root用户远程登录"
		stc.Action = "查看文件/etc/ssh/sshd_config中PermitRootLogin配置"
		stc.Standard = "no"
		stc.Actual = "no"
		stc.Protect = "修改/etc/ssh/sshd_config文件,配置PermitRootLogin no重启服务，/etc/init.d/sshd restart"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	fail := comm.GetCmdRes(`cat /etc/pam.d/system-auth | grep tally`)
	if fail != "" {
		stc.Name = "检查是否配置系统登录失败的策略"
		stc.Action = "查看文件/etc/pam.d/system-auth中登录失败配置"
		stc.Standard = "enable"
		stc.Actual = "enable"
		stc.Protect = "修改/etc/pam.d/system-auth文件,配置登录失败配置"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否配置系统登录失败的策略"
		stc.Action = "查看文件/etc/pam.d/system-auth中登录失败配置"
		stc.Standard = "enable"
		stc.Actual = "disable"
		stc.Protect = "修改/etc/pam.d/system-auth文件,配置登录失败配置"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	timeout := comm.GetCmdRes(`cat /etc/profile | grep TMOUT | awk -F'TMOUT=' '{print $2}'`)
	if numPattern(timeout) {
		timeout_, errTimeout := strconv.Atoi(min)
		if errTimeout != nil {
			log.Printf("err:%v", errTimeout)
		} else {
			if timeout_ < 300 {
				stc.Name = "检查是否设置命令行会话超时锁定"
				stc.Action = "查看/etc/profile中TMOUT配置"
				stc.Standard = 300
				stc.Actual = timeout_
				stc.Protect = "配置会话超时锁定时间标准值"
				stc.Status = "1"
				stc.Score = 3
				stc.Type = "认证授权"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			} else {
				stc.Name = "检查是否设置命令行会话超时锁定"
				stc.Action = "查看/etc/profile中TMOUT配置"
				stc.Standard = 300
				stc.Actual = timeout_
				stc.Protect = "配置会话超时锁定时间标准值"
				stc.Status = "0"
				stc.Score = 3
				stc.Type = "认证授权"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			}
		}
	} else {
		stc.Name = "检查是否设置命令行会话超时锁定"
		stc.Action = "查看/etc/profile中TMOUT配置"
		stc.Standard = 300
		stc.Actual = "no found"
		stc.Protect = "配置会话超时锁定时间标准值"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	emptypass := comm.GetCmdRes(`cat /etc/ssh/sshd_config | grep '^PermitEmptyPasswords yes'`)
	if emptypass != "" {
		stc.Name = "检查root登录时候是否允许空口令"
		stc.Action = "查看/etc/profile中TMOUT配置"
		stc.Standard = "disable"
		stc.Actual = "disable"
		stc.Protect = "删除或者加固可疑的用户权限以及口令配置"
		stc.Status = "1"
		stc.Score = 10
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查root登录时候是否允许空口令"
		stc.Action = "查看/etc/profile中TMOUT配置"
		stc.Standard = "disable"
		stc.Actual = "enable"
		stc.Protect = "删除或者加固可疑的用户权限以及口令配置"
		stc.Status = "0"
		stc.Score = 10
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	netrc := comm.GetCmdRes(`find  / -name  .rhosts && find  / -name  .netrc`)
	if netrc != "" {
		stc.Name = "检查远程连接的安全性配置"
		stc.Action = "查看系统是否存在.netrc、.rhosts文件"
		stc.Standard = "no"
		stc.Actual = netrc
		stc.Protect = "如无必要，删除这两个文件"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查远程连接的安全性配置"
		stc.Action = "查看系统是否存在.netrc、.rhosts文件"
		stc.Standard = "no"
		stc.Actual = "no"
		stc.Protect = "如无必要，删除这两个文件"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "认证授权"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	ssh := comm.GetCmdRes(`netstat -lnp | grep -E "ssh"`)
	if ssh != "" {
		stc.Name = "检查是否启用SSH协议"
		stc.Action = "查看netstat -lnp是否存在ssh服务应用"
		stc.Standard = "enable"
		stc.Actual = "enable"
		stc.Protect = "通过/etc/init.d/sshd start来启动SSH服务"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否启用SSH协议"
		stc.Action = "查看netstat -lnp是否存在ssh服务应用"
		stc.Standard = "enable"
		stc.Actual = "disable"
		stc.Protect = "通过/etc/init.d/sshd start来启动SSH服务"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	telnet := comm.GetCmdRes(`netstat -lnp | grep -E "telnet"`)
	if telnet != "" {
		stc.Name = "检查是否启用Telnet协议"
		stc.Action = "查看netstat -lnp是否存在telnet服务应用"
		stc.Standard = "disable"
		stc.Actual = "enable"
		stc.Protect = "编辑/etc/xinetd.d/telnet, 修改disable = yes"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否启用Telnet协议"
		stc.Action = "查看netstat -lnp是否存在telnet服务应用"
		stc.Standard = "disable"
		stc.Actual = "disable"
		stc.Protect = "编辑/etc/xinetd.d/telnet, 修改disable = yes"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	ftp := comm.GetCmdRes(`netstat -lnp | grep -E "ftp"`)
	if ftp != "" {
		stc.Name = "检查是否启用FTP协议"
		stc.Action = "查看netstat -lnp是否存在ftp服务应用"
		stc.Standard = "disable"
		stc.Actual = "enable"
		stc.Protect = "执行service ftp stop关闭ftp服务"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否启用FTP协议"
		stc.Action = "查看netstat -lnp是否存在ftp服务应用"
		stc.Standard = "disable"
		stc.Actual = "enable"
		stc.Protect = "执行service ftp stop关闭ftp服务"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	docker := comm.GetCmdRes(`netstat -lnp | grep -E "docker"`)
	if docker != "" {
		stc.Name = "检查是否启用Docker服务"
		stc.Action = "查看netstat -lnp是否存在docker服务应用"
		stc.Standard = "disable"
		stc.Actual = "enable"
		stc.Protect = "执行service docker stop关闭docker服务"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否启用Docker服务"
		stc.Action = "查看netstat -lnp是否存在docker服务应用"
		stc.Standard = "disable"
		stc.Actual = "disable"
		stc.Protect = "执行service docker stop关闭docker服务"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "协议安全"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	status := comm.GetCmdRes(`systemctl list-unit-files --type=service | grep "rsyslog" && systemctl list-unit-files --type=service | grep "auditd"`)
	if status != "" {
		stc.Name = "查看是否开启系统日志审计进程"
		stc.Action = "查看systemctl list-unit-files下是否开启auditd、rsyslog等日志审计进程。"
		stc.Standard = "enable"
		stc.Actual = "enable"
		stc.Protect = "建议配置专门的日志服务器，加强日志信息的异地同步备份"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "日志审计"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "查看是否开启系统日志审计进程"
		stc.Action = "查看systemctl list-unit-files下是否开启auditd、rsyslog等日志审计进程。"
		stc.Standard = "enable"
		stc.Actual = "disable"
		stc.Protect = "建议配置专门的日志服务器，加强日志信息的异地同步备份"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "日志审计"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	log_ := comm.GetCmdRes(`cat /etc/syslog.conf`)
	if log_ != "" {
		stc.Name = "查看是否配置syslog.conf"
		stc.Action = "查看systemctl list-unit-files下是否开启auditd、rsyslog等日志审计进程。"
		stc.Standard = "enable"
		stc.Actual = "enable"
		stc.Protect = "建议配置专门的日志服务器，加强日志信息的异地同步备份"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "日志审计"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "查看是否配置syslog.conf"
		stc.Action = "查看systemctl list-unit-files下是否开启auditd、rsyslog等日志审计进程。"
		stc.Standard = "enable"
		stc.Actual = "disable"
		stc.Protect = "建议配置专门的日志服务器，加强日志信息的异地同步备份"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "日志审计"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	banner := comm.GetCmdRes(`cat /etc/issue && cat /etc/issue.net`)
	if banner != "" {
		stc.Name = "检查是否修改系统banner"
		stc.Action = "查看/etc/issue和/etc/issue.net是否存在"
		stc.Standard = "yes"
		stc.Actual = "no"
		stc.Protect = "删除/etc目录下的 issue.net 和 issue 文件： # mv /etc/issue /etc/issue.bak # mv /etc/issue.net /etc/issue.net.bak"
		stc.Status = "0"
		stc.Score = 3
		stc.Type = "其他配置"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "检查是否修改系统banner"
		stc.Action = "查看/etc/issue和/etc/issue.net是否存在"
		stc.Standard = "yes"
		stc.Actual = "yes"
		stc.Protect = "删除/etc目录下的 issue.net 和 issue 文件： # mv /etc/issue /etc/issue.bak # mv /etc/issue.net /etc/issue.net.bak"
		stc.Status = "1"
		stc.Score = 3
		stc.Type = "其他配置"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	limits := comm.GetCmdRes(`cat /etc/security/limits.conf |grep -E '#@student|#*soft|#*hard|#@faculty'`)
	if limits != "" {
		stc.Name = "查看是否配置系统资源限度"
		stc.Action = "执行：cat /etc/security/limits.conf"
		stc.Standard = "enable"
		stc.Actual = "enable"
		stc.Protect = "查看系统资源限度是否合理进行调配"
		stc.Status = "1"
		stc.Score = 7
		stc.Type = "其他配置"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	} else {
		stc.Name = "查看是否配置系统资源限度"
		stc.Action = "执行：cat /etc/security/limits.conf"
		stc.Standard = "enable"
		stc.Actual = "disable"
		stc.Protect = "查看系统资源限度是否合理进行调配"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "其他配置"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

	passwd := comm.GetCmdRes(`cat /etc/passwd`)
	if passwd != "" {
		mode, errPasswd := comm.PrintPermissions("/etc/passwd")
		if errPasswd != nil {
			log.Printf("err:%v", errPasswd)
			stc.Name = "检查是否配置用户所需最小权限"
			stc.Action = "执行：cat /etc/security/limits.conf"
			stc.Standard = "644"
			stc.Actual = "no found"
			stc.Protect = "配置/etc/passwd权限为标准值644"
			stc.Status = "0"
			stc.Score = 7
			stc.Type = "账号口令"
			resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
		} else {
			if mode == "644" {
				stc.Name = "检查是否配置用户所需最小权限"
				stc.Action = "执行ls -la /etc/passwd查看文件权限"
				stc.Standard = "644"
				stc.Actual = mode
				stc.Protect = "配置/etc/passwd权限为标准值644"
				stc.Status = "1"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			} else {
				stc.Name = "检查是否配置用户所需最小权限"
				stc.Action = "执行：cat /etc/security/limits.conf"
				stc.Standard = "644"
				stc.Actual = mode
				stc.Protect = "配置/etc/passwd权限为标准值644"
				stc.Status = "0"
				stc.Score = 7
				stc.Type = "账号口令"
				resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
			}
		}
	} else {
		stc.Name = "检查是否配置用户所需最小权限"
		stc.Action = "执行：cat /etc/security/limits.conf"
		stc.Standard = "644"
		stc.Actual = "no found"
		stc.Protect = "配置/etc/passwd权限为标准值644"
		stc.Status = "0"
		stc.Score = 7
		stc.Type = "账号口令"
		resGet.ComplianceInfo = append(resGet.ComplianceInfo, stc)
	}

}
