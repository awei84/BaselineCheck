package getinfo

import (
	"BaselineCheck/comm"
	//"comm"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type BaseInfo struct {
	LanIp           string `json:"lan_ip"`
	WanIp           string `json:"wan_ip"`
	MacAddr         string `json:"macaddr"`
	Location        string `json:"location"`
	HostName        string `json:"hostname"`
	UpTime          string `json:"uptime"`
	DateTime        string `json:"datetime"`
	MappingPort     string `json:"mapping_port"`
	OsVendor        string `json:"osvendor"`
	SysIssue        string `json:"sys_issue"`
	KernelVersion   string `json:"kernel_version"`
	PatchInfo       string `json:"patch_info"`
	Virtual         string `json:"virtual"`
	CpuType         string `json:"cpu_type"`
	CpuNum          string `json:"cpu_num"`
	CpuCore         string `json:"cpu_core"`
	MemoryUsage     string `json:"memory_usage"`
	SwapPartition   string `json:"swap_partition"`
	DiskUsage       string `json:"disk_usage"`
	Description     string `json:"description"`
	PlatformVersion string `json:"platform_version"`
	PlatformNorm    string `json:"platform_norm"`
	Start           int    `json:"start"`
	End             int    `json:"end"`
}

// 获取主机ip地址
func (b *BaseInfo) GetHostIP() {
	ip := "127.0.0.1"
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {

		b.LanIp = ip
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = strings.Split(localAddr.String(), ":")[0]
	b.LanIp = ip
}

func (b *BaseInfo) GetHostIPLocation() {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://myip.ipip.net")
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
		// handle error
	}
	if strings.Contains(string(body), "IP") {
		location := strings.Split(string(body), "于：")[1]
		location = strings.Replace(location, " ", "-", -1)
		location = strings.Replace(location, "--", "-", -1)
		location = strings.Trim(location, " \n")
		b.Location = location // 获取ip物理地址
		reg, _ := regexp.Compile(`\d+\.\d+\.\d+\.\d+`)
		outip := reg.Find([]byte(string(body)))
		b.WanIp = string(outip) // 外网IP
	}
	//log.Println(string(body))
}

// 基础信息获取
func (b *BaseInfo) GetBaseInfo() {
	b.Start = int(time.Now().Unix())
	b.DateTime = comm.GetCmdRes(`date "+%Y-%m-%d %H:%M:%S"`)
	b.GetHostIP()
	b.GetHostIPLocation()
	cmdMacAddr := `ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
	b.MacAddr = comm.GetCmdRes(cmdMacAddr)                  // 获取mac地址
	b.HostName = comm.GetCmdRes(`hostname || echo Unknown`) // 获取主机名
	b.UpTime = comm.GetCmdRes(`uptime |awk '{print  $3,$4}'|cut -d, -f1 || echo Unknown`)
	cmdMappingPort := `netstat -lant 2>/dev/null | grep ":::$PORT.*LISTEN" |awk '/LISTEN/ {print $4}'  | awk  -F : '{print $NF}' | tr '\n' ' ' | sort|uniq|awk  -F : '{print $NF}' | tr '\n' ' ' | awk '{for(n=0;n++<NF;)a[n]=a[n]?a[n]FS$n:$n}END{for(n=0;n++<NF;)print a[n]}'`
	b.MappingPort = strings.Replace(comm.GetCmdRes(cmdMappingPort), "\n", ",", -1)
	b.OsVendor = comm.GetCmdRes(`dmidecode -s system-product-name 2> /dev/null || echo Unknown`)
	b.SysIssue = comm.GetCmdRes(`cat /etc/redhat-release || cat /etc/issue || echo Unknow`)
	b.KernelVersion = comm.GetCmdRes(`uname -r`)
	b.PatchInfo = strings.Replace(comm.GetCmdRes(`rpm -qa --last | grep patch`), "                     ", "  ", -1)
	b.Virtual = comm.GetCmdRes(`systemd-detect-virt`)
	b.CpuType = comm.GetCmdRes(`cat /proc/cpuinfo |grep name|cut -f2 -d:|uniq -c`)
	b.CpuNum = comm.GetCmdRes(`grep 'physical id' /proc/cpuinfo | sort | uniq | wc -l`)
	b.CpuCore = comm.GetCmdRes(`cat /proc/cpuinfo | grep "cpu cores"  | sort -u  | awk -F":" ' { print $2 } '  | sed -e 's/ *//'`)
	cmdMemoryUsage := `echo -e "$(free -m |grep -i mem |awk {'print $3'}) MiB / $(( $(free -m |grep -i mem |awk {'print $2'}) / 1024 )) GiB "`
	b.MemoryUsage = comm.GetCmdRes(cmdMemoryUsage)
	cmdSwapPartition := `echo -e "$(free -m |grep -i swap |awk {'print $3'}) MiB / $(( $(free -m |grep -i swap |awk {'print $2'}) / 1024 )) GiB"`
	b.SwapPartition = comm.GetCmdRes(cmdSwapPartition)
	cmdDiskUsage := `echo -e " $(df -TlH --total -t ext4 -t ext3 -t ext2 -t reiserfs -t jfs -t ntfs -t fat32 -t btrfs -t fuseblk -t zfs -t simfs -t xfs 2>/dev/null | grep -i total |awk {'print $4'})iB / $(df -TlH --total -t ext4 -t ext3 -t ext2 -t reiserfs -t jfs -t ntfs -t fat32 -t btrfs -t fuseblk -t zfs -t simfs -t xfs 2>/dev/null | grep -i total |awk {'print $3'})iB "`
	b.DiskUsage = comm.GetCmdRes(cmdDiskUsage)
	b.PlatformVersion = "V1.3C00413P"
	b.PlatformNorm = "CIS基线配置规范(Linux)"
	fmt.Println("[1/4] Baseline baseInfo data check finished!")
}
