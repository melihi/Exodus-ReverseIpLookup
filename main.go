package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gocolly/colly"
)

var hosts []string

func main() {
	var wg sync.WaitGroup

	wg.Add(4)

	color.Green(`
___________                .___            
\_   _____/__  _______   __| _/_ __  ______
 |    __)_\  \/  /  _ \ / __ |  |  \/  ___/
 |        \>    <  <_> ) /_/ |  |  /\___ \ 
/_______  /__/\_ \____/\____ |____//____  >
        \/      \/          \/          \/ 

	`)
	color.Red("Reverse ip lookup tool by Melih Isbilen | ציאת מצרים v1.0 | github.com/melihi")
	ipAdress := flag.String("ip", "", "Ip adress of target .")
	viewDnsApiKey := flag.String("viewDns", "", "ViewDns api key .")
	spyseApiKey := flag.String("spyse", "", "Spyse api key .")
	verboseMode := flag.Bool("v", false, "Enable verbose mode")
	outpuFile := flag.String("o", "-", "Enable output file path")
	flag.Parse()
	if *ipAdress == "" {
		panic("Ip address required !")
	}
	dt := time.Now()
	color.Yellow("[>] Target ip : %v\n", *ipAdress)
	//Format MM-DD-YYYY hh:mm:ss
	color.Yellow("[>] Start     : %v\n\n", dt.Format(time.UnixDate))

	go bingCrawl(*ipAdress, &wg)

	if viewDnsApiKey != nil {
		go viewDnsCrawl(*ipAdress, *viewDnsApiKey, &wg)

	}
	if spyseApiKey != nil {
		go spyseCralw(*ipAdress, *spyseApiKey, &wg)

	}
	go hackertargetCralw(*ipAdress, &wg)
	wg.Wait()

	finish(*verboseMode, *outpuFile)
}

func finish(verb bool, out string) {
	removeDup()
	color.Green("[+] Captured hosts : %d\n", len(hosts))
	dt := time.Now()
	color.Yellow("\n[>] Finish     : %v", dt.Format(time.UnixDate))
	if out != "-" {
		f, err := os.Create(out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		for _, value := range hosts {
			fmt.Fprintln(f, value) // print values to f, one per line
		}

	}

	if verb {
		for _, i := range hosts {
			color.Green("%s", i)
		}
	}
}
func httpReq(url string, getParams map[string]string, httpMethod string, httpHeaders map[string]string, postData string) string {
	client := &http.Client{}

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer([]byte(postData)))
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36")
	//ADD HTTP HEADERS
	for key, element := range httpHeaders {
		req.Header.Add(key, element)
	}
	//ADD GET URL PARAMETERS
	q := req.URL.Query()
	for key, element := range getParams {
		q.Add(key, element)
	}
	req.URL.RawQuery = q.Encode()
	//do request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)

	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)

	}

	return string(responseBody)
}
func bingCrawl(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	color.Green("[!] Bing.com crawling started .")
	var bingPage int = 1
	for i := 1; i < 10; i++ {
		scrape("https://www.bing.com/search?q=ip%3A+"+ip+"&first="+strconv.Itoa(bingPage), ".b_title .sh_favicon")
		bingPage += 10
	}

}
func viewDnsCrawl(ip string, apiKey string, wg *sync.WaitGroup) {
	defer wg.Done()
	color.Green("[!] ViewDns.info crawling started .")
	var params = map[string]string{"host": ip, "apikey": apiKey, "output": "json"}
	var result string = httpReq("https://api.viewdns.info/reverseip/", params, "GET", nullMap, "")
	var api viewDnsStruct

	err := json.Unmarshal([]byte(result), &api)
	if err != nil {
		fmt.Println(err)
	}
	//split [{domain.com 2022-01-01} {domain.com 2022-01-01}]
	y := strings.Split(string(fmt.Sprintf("%s", api.Response.Domains)), " ")
	var tempArr []string
	for i, word := range y {
		tempArr = strings.Split(word, " ")
		tempArr[0] = strings.Replace(tempArr[0], "[", "", -1)
		tempArr[0] = strings.Replace(tempArr[0], "{", "", -1)
		//grep domains ignore dates
		if i%2 == 0 {
			hosts = append(hosts, tempArr[0])
		}
	}

}
func hackertargetCralw(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	color.Green("[!] Hackertarget.com crawling started .")
	//url get parameter map
	var params = map[string]string{"q": ip}

	var data string = httpReq("https://api.hackertarget.com/reverseiplookup/", params, "GET", nullMap, "")
	//parse line by line multiline string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		hosts = append(hosts, scanner.Text()+"hackertargetr")
	}

}
func spyseCralw(ip string, apiKey string, wg *sync.WaitGroup) {
	defer wg.Done()
	color.Green("[!] Spyse.com crawling started .")
	//http header map for spyse api
	var header = map[string]string{"accept": "application/json", "Authorization": "Bearer " + apiKey,
		"Content-Type": "application/json"}
	//http post data for spyse api
	var postData string = "{\"limit\":100,\"offset\":0,\"search_params\":[{\"dns_a\":{\"operator\":\"eq\",\"value\":\"" + ip + "\"}}],\"query\":\"\"}"
	var result string = httpReq("https://api.spyse.com/v4/data/domain/search", nullMap, "POST", header, postData)

	//Grep "host":"domain.com" from json data
	r := regexp.MustCompile(`"host":"([^"]*)"`)
	matches := r.FindAllString(result, -1)
	//edit data with loop
	for _, matc := range matches {
		//clear host":
		matc = strings.Replace(matc, "host\":", "", -1)
		//clear quotes
		matc = strings.Replace(matc, "\"", "", -1)
		if matc != "" {
			hosts = append(hosts, matc)

		}
	}

}
func scrape(url string, classes string) {
	c := colly.NewCollector(colly.MaxDepth(1))

	c.OnHTML(classes, func(e *colly.HTMLElement) {
		link := e.Attr("href")
		//if href attr length equal zero grep html text
		if len(link) == 0 {
			link = e.Text
		}
		//Clear http , https and www for reducing duplicate results
		link = strings.Replace(link, "https://", "", -1)
		link = strings.Replace(link, "http://", "", -1)
		link = strings.Replace(link, "www.", "", -1)
		m1 := regexp.MustCompile(`/.*`)
		link = m1.ReplaceAllString(link, "")
		hosts = append(hosts, link)
	})
	c.Visit(url)
}
func removeDup() {
	//remove duplicate values
	inResult := make(map[string]bool)
	var result []string
	for _, str := range hosts {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}
	color.Green("\n[+] Removed duplicate results : %d", len(hosts)-len(result))
	hosts = result

}
