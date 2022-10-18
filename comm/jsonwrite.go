package comm

import (
	"log"
	"os"
)

func JsonWrite(data []byte) {
	fp, err := os.OpenFile("result.json", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Println(err)
	}
	defer fp.Close()
	_, err = fp.Write(data)
	if err != nil {
		log.Println(err)
	}
}
