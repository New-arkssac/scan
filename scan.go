package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type workScan struct {
	ip, port               string
	num, breakNum, quitNum int
	webJob                 chan string
	quit                   chan bool
	successWeb, failWeb    map[string][]string
	notWeb                 map[string]string
	portMsg                map[string]string
	abnormal               map[string]string
	rw                     *sync.RWMutex
}

type m struct {
	SUCCESS  map[string][]string `json:"SUCCESS"`
	FAIL     map[string][]string `json:"FAIL"`
	NOTWEB   map[string]string   `json:"NOTWEB"`
	ABNORMAL map[string]string   `json:"ABNORMAL"`
}

var (
	fileName, folderFileName string
	goroutines               int
	help                     bool
	tr                       = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client  = &http.Client{Transport: tr, Timeout: 2 * time.Second}
	chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36"
	firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0"
)

func init() {
	flag.BoolVar(&help, "h", false, "帮助文档")
	flag.StringVar(&fileName, "e", "", "`excel`文件路径, 不支持XLS且不能为空")
	flag.StringVar(&folderFileName, "f", "", "`字典文件`路径")
	flag.IntVar(&goroutines, "g", 10, "`go程`数量")
	flag.Usage = usage
}

func (w *workScan) getHost() {
	f, err := excelize.OpenFile(fileName)
	if err != nil {
		log.Println(err)
		return
	}
	rows, no := f.Rows("Sheet1")
	if no != nil {
		log.Println(no)
		return
	}
	for rows.Next() {
		row, cloErr := rows.Columns()
		if cloErr != nil {
			return
		}
		if len(row) <= 2 {
			continue
		}
		w.num++
		if w.num == 1 {
			continue
		}
		if b, ipErr := regexp.MatchString(`\d+.\d+.\d+.\d+`, row[1]); b && ipErr == nil {
			w.ip = row[1]
		}
		if strings.Contains(row[2], "/tcp") {
			w.port = strings.Split(row[2], "/tcp")[0]
		}
		w.webJob <- fmt.Sprintf("%s:%s", w.ip, w.port)
	}
	if closeErr := f.Close(); closeErr != nil {
		fmt.Println(closeErr)
	}
}

func (w *workScan) getMsgPort(host string) string {
	var (
		buf [1024]byte
		msg string
	)
	conn, err := net.DialTimeout("tcp", host, 1*time.Second)
	if err != nil {
		return "CLOSE or FILTER"
	}
	writer := bufio.NewWriter(conn)
	if strings.Contains(host, "2181") {
		_, _ = writer.Write([]byte("envi"))
	}
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if n, no := conn.Read(buf[:]); no != nil {
		msg = "message: nil\r"
	} else {
		msg = fmt.Sprintf("message: [%s]\n", strings.TrimSpace(string(buf[:n])))
	}
	_ = conn.Close()
	fmt.Printf("%s %s", host, msg)
	return msg
}

func (w *workScan) setRequest(ua, host, url, https string) {
	w.breakNum++
	requestHttp, no := http.NewRequest("GET", url, nil)
	requestHttps, no1 := http.NewRequest("GET", https, nil)
	if no != nil || no1 != nil {
		fmt.Println("host err:", no)
		w.rw.Lock()
		w.abnormal[host] = "ABNORMAL"
		w.rw.Unlock()
		goto counter
	}
	requestHttp.Header.Set("User-Agent", ua)
	requestHttps.Header.Set("User-Agent", ua)
	w.httpNetScan(requestHttp, requestHttps, host, ua, url, https)
counter:
	w.quitNum++
	runtime.Gosched()
	if w.quitNum == w.breakNum {
		time.Sleep(2 * time.Second)
		w.quit <- true
	}
	return
}

func (w *workScan) httpNetScan(url, https *http.Request, host, ua, requestHttp, requestHttps string) {
	var requestUrl = requestHttp
	var response *http.Response
	ok, reErr := regexp.MatchString(`\w/\S+$`, host)
	if reErr != nil {
		fmt.Println(reErr)
	}
	response1, err := client.Do(url)
	response = response1
	if err != nil || response.StatusCode != 200 {
		response2, no := client.Do(https)
		requestUrl = requestHttps
		response = response2
		if no != nil {
			if ok {
				return
			}
			msg := w.getMsgPort(host)
			msg = strings.TrimSpace(msg)
			w.rw.Lock()
			w.notWeb[host] = fmt.Sprintf("NOT WEB %s", msg)
			w.rw.Unlock()
			return
		}
		if response.StatusCode != 200 {
			if ua == firefox {
				if folderFileName != "" && !ok {
					go w.rangeFolder(host)
				}
				w.responseBodyRead(response, "firefox", requestUrl)
				return
			}
			w.setRequest(firefox, host, requestHttp, requestHttps)
		}
	}
	if folderFileName != "" && !ok {
		go w.rangeFolder(host)
	}
	w.responseBodyRead(response, "chrome", requestUrl)
}

func (w *workScan) responseBodyRead(response *http.Response, ua, requestUrl string) {
	var (
		text, msg string
	)
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.rw.Lock()
		w.failWeb[requestUrl] = append(w.failWeb[requestUrl], "error")
		w.rw.Unlock()
		fmt.Printf("%s RESPONSE BODY ERR\r", requestUrl)
		return
	}
	content := regexp.MustCompile(`(?i)<title>(.*?)</title>`).FindStringSubmatch(string(body))
	if len(content) != 0 {
		text = content[len(content)-1]
	} else {
		text = string(body)
	}
	if response.StatusCode == 200 {
		msg = fmt.Sprintf("%s %s %s", ua, response.Status, text)
		w.rw.Lock()
		w.successWeb[requestUrl] = append(w.successWeb[requestUrl], msg)
		w.rw.Unlock()
	} else {
		msg = fmt.Sprintf("%s %s %s", ua, response.Status, text)
		w.rw.Lock()
		w.failWeb[requestUrl] = append(w.failWeb[requestUrl], msg)
		w.rw.Unlock()
	}
	fmt.Println(requestUrl, msg)
	if bodyCloseErr := response.Body.Close(); bodyCloseErr != nil {
		fmt.Println(bodyCloseErr)
	}
	return
}

func (w *workScan) rangeFolder(host string) {
	file, err := os.Open(folderFileName)
	if err != nil {
		fmt.Println(err)
	}
	content := bufio.NewScanner(file)
	for {
		if !content.Scan() {
			break
		}
		w.webJob <- fmt.Sprintf("%s/%s", host, strings.TrimSpace(content.Text()))
	}
	if closeErr := file.Close(); closeErr != nil {
		return
	}
}

func (w *workScan) start() {
	var (
		mj  = m{}
		f   *os.File
		err error
	)
	fmt.Printf("开始扫描%s……\n", fileName)
	name1 := regexp.MustCompile(`-\d+`).FindString(fileName)
	name2 := "工单" + name1 + "-" + time.Now().Format("20060102") + ".json"
	for i := 0; i < goroutines; i++ {
		go w.goroutine()
	}
	go w.getHost()
	<-w.quit
	fmt.Printf("%s\r", strings.Repeat(" ", 100))
	fmt.Printf("一共测试了:%d个地址\n", w.quitNum)
	mj.FAIL = w.failWeb
	mj.NOTWEB = w.notWeb
	mj.SUCCESS = w.successWeb
	mj.ABNORMAL = w.abnormal
	if !checkFile(name2) {
		f, err = os.Create(name2)
		if err != nil {
			panic(err)
		}
	} else {
		f, err = os.OpenFile(name2, os.O_WRONLY, 2)
		if err != nil {
			panic(err)
		}
	}
	encode := json.NewEncoder(f)
	fmt.Printf("开始写入%s……\n", name2)
	encode.SetIndent("", "    ")
	if err = encode.Encode(mj); err != nil {
		panic(err)
	}
	if closeErr := f.Close(); closeErr != nil {
		return
	}
	fmt.Printf("%s写入完成!\n", name2)
}

func (w *workScan) close() {
	close(w.webJob)
	close(w.quit)
}

func (w *workScan) goroutine() {
	for i := range w.webJob {
		url := fmt.Sprintf("http://%s", i)
		https := fmt.Sprintf("https://%s", i)
		w.setRequest(chrome, i, url, https)
	}
}

func scanBody() *workScan {
	w := &workScan{
		webJob:     make(chan string, int(float64(goroutines)*0.8)),
		quit:       make(chan bool),
		successWeb: make(map[string][]string),
		failWeb:    make(map[string][]string),
		notWeb:     make(map[string]string),
		abnormal:   make(map[string]string),
		rw:         new(sync.RWMutex),
	}
	return w
}

func checkFile(fileName string) bool {
	if _, err := os.Stat(fileName); err != nil {
		return false
	}
	return true
}

func usage() {
	if _, err := fmt.Fprintf(os.Stderr, "帮助文档:\n"); err != nil {
		return
	}
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		return
	}
	if !strings.Contains(fileName, "xlsx") {
		fmt.Printf(`温馨提醒:
	请使用 -h 参数查看帮助文档`)
		return
	}
	t := time.Now()
	w := scanBody()
	w.start()
	w.close()
	fmt.Printf("共耗时: %v", time.Since(t))
}
