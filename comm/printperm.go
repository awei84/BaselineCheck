package comm

import (
	"os"
	"strconv"
)

func strtoint(stringInt string) (strInt int) {
	strInt, _ = strconv.Atoi(stringInt)
	return
}

// 把类似-rwxrwxrwx转为777
func PrintPermissions(filename string) (mode string, err error) {
	info, err := os.Stat(filename)
	if err != nil {
		return
	}
	mod := info.Mode().String()[1:]
	modbyte := []byte(mod)
	for i := 0; i < len(mod); i++ {
		switch string(mod[i]) {
		case "r":
			modbyte[i] = '4'
		case "w":
			modbyte[i] = '2'
		case "x":
			modbyte[i] = '1'
		default:
			modbyte[i] = '0'
		}
	}
	modbyte_ := string(modbyte)
	modoF := strconv.Itoa(strtoint(modbyte_[0:1]) + strtoint(modbyte_[1:2]) + strtoint(modbyte_[2:3]))
	modoS := strconv.Itoa(strtoint(modbyte_[3:4]) + strtoint(modbyte_[4:5]) + strtoint(modbyte_[5:6]))
	modoT := strconv.Itoa(strtoint(modbyte_[6:7]) + strtoint(modbyte_[7:8]) + strtoint(modbyte_[8:9]))
	mode = modoF + modoS + modoT
	return
}
