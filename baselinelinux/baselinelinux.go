package baselinelinux

import (
	"BaselineCheck/comm"
	"BaselineCheck/getinfo"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type Result struct {
	BaseInfo       getinfo.BaseInfo               `json:"base_info"`
	TrojanInfo     []getinfo.SingleTrojanInfo     `json:"trojan_info"`
	EmergencyInfo  getinfo.EmergencyInfo          `json:"emergency_info"`
	ComplianceInfo []getinfo.SingleComplianceInfo `json:"compliance_info"`
}


func Run() {
	fmt.Println(`
		==================================
		*      Linux  基线检查工具       	 *
		*      author:awei84             *
		*      version:V1.3C00413P       *
		==================================`)
	log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)
	var r Result
	var bs getinfo.BaseInfo
	bs.GetBaseInfo()
	r.BaseInfo = bs

	r.TrojanInfo = getinfo.ReturnResultTro()

	var eg getinfo.EmergencyInfo
	eg.GetEmergencyInfo()
	r.EmergencyInfo = eg

	r.ComplianceInfo = getinfo.ReturnResultCom()

	r.BaseInfo.Description = "基线检查任务"
	r.BaseInfo.End = int(time.Now().Unix())

	res, err := json.MarshalIndent(r, "", "  ") // 格式化编码
	if err != nil {
		log.Println("JSON ERR:", err)
	}
	fmt.Println("[✓] Baseline check finish!")
	comm.JsonWrite(res) // 把结果写入文件
}
