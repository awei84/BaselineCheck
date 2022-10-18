package comm

import (
	"os/exec"
	"strings"
)

func GetCmdRes(cmd string) (cmdres string) {
	out, err := exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil {
		// log.Printf("err:%v out:%v\n", err, string(out))
		// log.Printf("Error:The command %v is err, %v\n", cmd, err)
		// return  TODO: 报错也输出数据
	}
	cmdres = strings.Trim(string(out), " \n")
	return
}
