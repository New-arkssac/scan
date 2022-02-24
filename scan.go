package main

import (
	"bufio"
	"crypto/tls"
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
	ip, port                                    string
	num, breakNum                               int
	webJob, portJob, finishJob, failJob, finish chan string
	content                                     *bufio.Scanner
	file                                        *os.File
	quit                                        chan bool
	//	m map[string]interface{}
	successWeb, failWeb, notWeb map[string][]string
	portMsg                     map[string]string
	rw                          *sync.RWMutex
}

var (
	fileName, folderFileName      string
	goroutines, jobNum, finishNum int
	tr                            = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client  = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36"
	firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0"
)

func init() {
	flag.StringVar(&fileName, "e", "", "excel文件路径")
	flag.StringVar(&folderFileName, "f", "1.txt", "字典文件路径")
	flag.IntVar(&goroutines, "g", 10, "go程数量")
	flag.IntVar(&jobNum, "J", 10, "工作缓存区")
	flag.IntVar(&finishNum, "F", 10, "完成缓存区")
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
}

func (w *workScan) getMsgPort(host string) {
	var (
		buf [1024]byte
	)
	conn, err := net.DialTimeout("tcp", host, 1*time.Second)
	if err != nil {
		w.rw.Lock()
		w.portMsg[host] = "CLOSE"
		w.rw.Unlock()
		return
	}
	writer := bufio.NewWriter(conn)
	switch {
	case strings.Contains(host, "2181"):
		_, _ = writer.Write([]byte("envi"))
	default:
		_, _ = writer.Write([]byte("help"))
	}
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if n, no := conn.Read(buf[:]); no != nil {
		w.rw.Lock()
		msg := fmt.Sprintf("%s message: nil", host)
		w.notWeb["port"] = append(w.notWeb["port"])
		w.rw.Unlock()
		w.finish <- msg
	} else {
		w.rw.Lock()
		msg := fmt.Sprintf("%s message: %s\r", host, strings.TrimSpace(string(buf[:n])))
		w.notWeb["port"] = append(w.notWeb["port"], msg)
		w.rw.Unlock()
		w.finish <- msg
	}
	_ = conn.Close()
	defer runtime.Goexit()
}

func (w *workScan) setRequest(ua, host, url, https string) {
	requestHttp, _ := http.NewRequest("GET", url, nil)
	requestHttps, _ := http.NewRequest("GET", https, nil)
	requestHttp.Header.Set("User-Agent", ua)
	requestHttps.Header.Set("User-Agent", ua)
	w.httpNetScan(requestHttp, requestHttps, host, ua, url, https)
}

func (w *workScan) httpNetScan(url, https *http.Request, host, ua, requestHttp, requestHttps string) {
	var requestUrl = requestHttp
	var response *http.Response
	ok, reErr := regexp.MatchString(`(?i)\w/\S+$`, host)
	if reErr != nil {
		fmt.Println(reErr)
	}
	response1, err := client.Do(url)
	response = response1
	if err != nil || response1.StatusCode != 200 {
		response2, no := client.Do(https)
		requestUrl = requestHttps
		response = response2
		if no != nil && !ok {
			w.portJob <- host
			return
		}
		if response2.StatusCode != 200 {
			if ua == firefox {
				if !ok {
					go w.rangeFolder(host)
				}
				w.responseBodyRead(response, requestUrl)
				return
			}
			w.setRequest(firefox, host, requestHttp, requestHttps)
		}
	}
	if !ok {
		go w.rangeFolder(host)
	}
	w.responseBodyRead(response, requestUrl)
	defer runtime.Goexit()
}

func (w *workScan) responseBodyRead(response *http.Response, requestUrl string) {
	var text string
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.rw.Lock()
		w.failWeb[requestUrl] = append(w.failWeb[requestUrl], "error")
		w.rw.Unlock()
		return
	}
	content := regexp.MustCompile(`<title>(.*?)</title>`).FindStringSubmatch(string(body))
	if len(content) != 0 {
		text = content[len(content)-1]
	} else {
		text = ""
	}
	switch {
	case response.StatusCode == 200:
		msg := fmt.Sprintf("%s %s %s", requestUrl, response.Status, text)
		w.rw.Lock()
		w.successWeb["SUCCESS"] = append(w.successWeb["SUCCESS"], msg)
		w.rw.Unlock()
		w.finish <- fmt.Sprintf("%s\n", msg)
	default:
		msg := fmt.Sprintf("%s %s %s", requestUrl, response.Status, text)
		w.rw.Lock()
		w.failWeb["FAIL"] = append(w.successWeb["FAIL"], msg)
		w.rw.Unlock()
		w.finish <- fmt.Sprintf("%s\r", msg)
	}
}

func (w *workScan) rangeFolder(host string) {
	for {
		if !w.content.Scan() {
			break
		}
		w.webJob <- fmt.Sprintf("%s/%s", host, strings.TrimSpace(w.content.Text()))
	}
	runtime.Goexit()
}

func scanBody() *workScan {
	w := &workScan{
		webJob:    make(chan string, jobNum),
		portJob:   make(chan string, jobNum),
		finishJob: make(chan string, jobNum),
		failJob:   make(chan string, jobNum),
		finish:    make(chan string),
		quit:      make(chan bool),
		//m: make(map[string]interface{}),
		successWeb: make(map[string][]string),
		failWeb:    make(map[string][]string),
		notWeb:     make(map[string][]string),
		portMsg:    make(map[string]string),
		rw:         new(sync.RWMutex),
	}
	return w
}

func (w *workScan) start() {
	fmt.Println("start……")
	file, err := os.Open(folderFileName)
	w.file = file
	if err != nil {
		fmt.Println(err)
		return
	}
	w.content = bufio.NewScanner(file)
	for i := 0; i < goroutines; i++ {
		go w.goroutine()
	}
	go w.getHost()
	<-w.quit
	w.close()
}

func (w *workScan) close() {
	close(w.portJob)
	close(w.webJob)
	close(w.finish)
	close(w.quit)
	if err := w.file.Close(); err != nil {
		return
	}
}

func (w *workScan) goroutine() {
	for {
		select {
		case i := <-w.webJob:
			url := fmt.Sprintf("http://%s", i)
			https := fmt.Sprintf("https://%s", i)
			go w.setRequest(chrome, i, url, https)
		case i := <-w.portJob:
			go w.getMsgPort(i)
		case i := <-w.finish:
			fmt.Printf(i)
		}
	}
}

func main() {
	flag.Parse()
	w := scanBody()
	w.start()
}
