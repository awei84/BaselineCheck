package getinfo

import (
	"BaselineCheck/comm"
	"fmt"
)

type EmergencyInfo struct {
	Usersudo        string `json:"usersudo"`
	Userroot        string `json:"userroot"`
	Userclone       string `json:"userclone"`
	Sshpasswd       string `json:"sshpasswd"`
	Sshuser         string `json:"sshuser"`
	Sshsuccess      string `json:"sshsuccess"`
	Sshcrack        string `json:"sshcrack"`
	Sshversion      string `json:"sshversion"`
	Processserver   string `json:"processserver"`
	Processport     string `json:"processport"`
	Processcputtop5 string `json:"processcputtop5"`
	Processcput15   string `json:"processcput15"`
	Processramttop5 string `json:"processramttop5"`
	Filechange      string `json:"filechange"`
	Filebig         string `json:"filebig"`
	Filescript      string `json:"filescript"`
	Filespace       string `json:"filespace"`
	Filemd5         string `json:"filemd5"`
	Configiptables  string `json:"configiptables"`
	Configrouter    string `json:"configrouter"`
	Configcrontab   string `json:"configcrontab"`
	Logmessages     string `json:"logmessages"`
	Logrsyslog      string `json:"logrsyslog"`
}

func (g *EmergencyInfo) GetEmergencyInfo() {
	g.Usersudo = comm.GetCmdRes(`cat /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"`)
	g.Userroot = comm.GetCmdRes(`awk -F: '$3==0{print $1}' /etc/passwd`)
	g.Sshuser = comm.GetCmdRes(`cat /etc/passwd|grep -E "/bin/bash$" |awk -F: '{print $1}'`)
	g.Sshsuccess = comm.GetCmdRes(`grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' /var/log/secure | sort | uniq`)
	g.Sshcrack = comm.GetCmdRes(`grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c | awk -F: --re-interval '{match($0,/([0-9]{1,3}\.){3}[0-9]{1,3}/,a); print a[0]}'`)
	g.Sshversion = comm.GetCmdRes(`stat /usr/sbin/sshd`)
	g.Processserver = comm.GetCmdRes(`systemctl list-units --type=service --state=running |grep ".service"`)
	g.Processport = comm.GetCmdRes(`netstat -lntup|grep -v "Active Internet"`)
	g.Processcputtop5 = comm.GetCmdRes(`ps -auxf | sort -nr -k 3 | head -5`)
	g.Processcput15 = comm.GetCmdRes(`ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=15) print $2,$3}'`)
	g.Processramttop5 = comm.GetCmdRes(`ps -auxf | sort -nr -k 4 | head -5`)
	g.Filechange = comm.GetCmdRes(`find / -type f -mtime 3`)
	g.Filebig = comm.GetCmdRes(`find / -type f -size +100M -print0 | xargs -0 du -h | sort -nr`)
	// 数据可能过多，最多获取后200行
	g.Filescript = comm.GetCmdRes(`find / *.* | grep -E "\.(py|sh|per|pl)$" | grep -Ev "/usr|/etc|/var" | tail -n 200`)
	g.Filespace = comm.GetCmdRes(`find / -name ". " -print || find / -name ".. " -print || find / -name " " -print`)
	g.Filemd5 = comm.GetCmdRes(`md5sum /bin/ls /usr/bin/find /usr/bin/ps`)
	g.Configiptables = comm.GetCmdRes(`iptables -L | grep "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}"`)
	g.Configrouter = comm.GetCmdRes(`cat /proc/sys/net/ipv4/ip_forward | gawk -F: '{if ($1==1) print "1"}'`)
	g.Configcrontab = comm.GetCmdRes(`crontab  -l`)
	g.Logmessages = comm.GetCmdRes(`cat /var/log/messages |head -40`)
	g.Logrsyslog = comm.GetCmdRes(`cat /etc/rsyslog.conf | grep -Ev "#|^$"`)
	fmt.Println("[3/4] Baseline emergencyInfo data check finished!")
}
