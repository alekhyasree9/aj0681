package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

var ipt *iptables.IPTables
var syslogPath = "/var/log/syslog"
var JWTSecret = []byte("somesecretkey####1!09803223@!2")
type BlockedLog struct{
	Timestamp time.Time `json:"timestamp"`
	SourceIP string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	BlockedReason string `json:"blocked_reason"`
}

func main(){
	var err error
	//create iptable
	ipt,err = iptables.New()
	if err != nil{
		fmt.Printf("Error initializing iptables: %v\n",err)
		os.Exit(1)
	}
	//create echo
	e:=echo.New()
	e.Use(middleware.Static("static"))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
	}))
	// e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
	// 	SigningKey: JWTSecret,
	// }))
	e.GET("/",func(c echo.Context) error {
		return c.File("static/index.html")
	})
	e.POST("/login",login)
	authenticatedGroup := e.Group("")
	authenticatedGroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: JWTSecret,
	}))
	e.GET("/statistics",func(c echo.Context) error {
		return c.File("static/statistics.html")
	})
	authenticatedGroup.POST("/block/ip",blockIP)
	authenticatedGroup.POST("/unblock/ip",unblockIP)
	authenticatedGroup.POST("/block/port",blockPort)
	authenticatedGroup.POST("/unblock/port",unblockPort)
	authenticatedGroup.POST("/block/protocol",blockProtocol)
	authenticatedGroup.POST("/unblock/protocol",unblockProtocol)
	authenticatedGroup.POST("/block/country",blockCountry)
	authenticatedGroup.POST("/unblock/country",unblockCountry)
	authenticatedGroup.POST("/block/limitrate",blockLimitRate)
	authenticatedGroup.POST("/block/unblocklimitrate",unblockLimitRate)
	authenticatedGroup.GET("/logs",getLogs)
	authenticatedGroup.GET("/rules",getRules)
	authenticatedGroup.GET("/getStatisticsout",getStatisticsout)
	authenticatedGroup.GET("/getStatisticsin",getStatisticsin)
	err1 := e.Start(":1323")
	if(err1!=nil){
		fmt.Sprintln("Unable to start the server")
	}
}
func getStatisticsout(c echo.Context) error{
	table:="filter"
	cmd:=exec.Command("iptables","-t",table,"-nvxL","OUTPUT")
	output,err:=cmd.CombinedOutput()
	if err!=nil{
		return c.JSON(500,map[string]string{"error":"Unable to fetch statistics"})
	}
	lines:=strings.Split(string(output),"\n")
	count:=1
	var s []string
	regex:=regexp.MustCompile(`\s+`)
	for _,line:=range lines{
		if(count<3){
			count++
			continue
		}

		line = strings.TrimSpace(line)
		if line!=""{
		fields:=regex.Split(line,-1)
		s=append(s,fmt.Sprintf("Rule %d: Packets Blocked: %s, Bytes Blocked: %s",count-2,fields[0],fields[1]))
		}
		count++
	}
	return c.JSON(200,s)
}
func getStatisticsin(c echo.Context) error{
	table:="filter"
	cmd:=exec.Command("iptables","-t",table,"-nvxL","INPUT")
	output,err:=cmd.CombinedOutput()
	if err!=nil{
		return c.JSON(500,map[string]string{"error":"Unable to fetch statistics"})
	}
	lines:=strings.Split(string(output),"\n")
	count:=1
	var s []string
	regex:=regexp.MustCompile(`\s+`)
	for _,line:=range lines{
		if(count<3){
			count++
			continue
		}

		line = strings.TrimSpace(line)
		if line!=""{
		fields:=regex.Split(line,-1)
		s=append(s,fmt.Sprintf("Rule %d: Packets Blocked: %s, Bytes Blocked: %s",count-2,fields[0],fields[1]))
		}
		count++
	}
	return c.JSON(200,s)
}
func login(c echo.Context) error{
	type Login struct{
		Username string `json:"username"`
		Password string `json:"password"`
	}
	req := new(Login)
	if err:=c.Bind(req);err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.Username == "admin" && req.Password=="admin1"{
		token:=jwt.New(jwt.SigningMethodHS256)
		claims:=token.Claims.(jwt.MapClaims)
		claims["username"]=req.Username
		claims["exp"]=time.Now().Add(time.Hour*24).Unix()
		tokenString,err:=token.SignedString(JWTSecret)
		if err!=nil{
			return c.JSON(500,map[string]string{"error":"Failed to validate User"})
		}
		return c.JSON(200,map[string]string{"token":tokenString})
	}else{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
}
func blockLimitRate(c echo.Context) error{
	type BlockIP struct{
		IP string `json:"ip"`
		NUMBER int `json:"number"`
		RATE string `json:"rate"`
	}
	req:= new(BlockIP)
	if err:=c.Bind(req); err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	//check if ip address is valid
	ip:=net.ParseIP(req.IP)
	if ip==nil{
		return c.JSON(400,map[string]string{"error":"Invalid IP address"})
	}
	if req.RATE!="second" && req.RATE!="min" && req.RATE!="hour"{
		return c.JSON(400,map[string]string{"error":"Invalid time. It can be second, minute or hour"})
	}
	//add new rule to block that IP
	if req.RATE=="second"{
	err:=ipt.AppendUnique("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/second",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
	if err !=nil{
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.RATE=="min"{
		err:=ipt.AppendUnique("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/min",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	if req.RATE=="hour"{
		err:=ipt.AppendUnique("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/hour",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	return c.JSON(200,map[string]string{"message":"ip blocking success"})
}
func unblockLimitRate(c echo.Context) error{
	type BlockIP struct{
		IP string `json:"ip"`
		NUMBER int `json:"number"`
		RATE string `json:"rate"`
	}
	req:= new(BlockIP)
	if err:=c.Bind(req); err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	//check if ip address is valid
	ip:=net.ParseIP(req.IP)
	if ip==nil{
		return c.JSON(400,map[string]string{"error":"Invalid IP address"})
	}
	if req.RATE!="second" && req.RATE!="min" && req.RATE!="hour"{
		return c.JSON(400,map[string]string{"error":"Invalid time. It can be second, minute or hour"})
	}
	//add new rule to block that IP
	if req.RATE=="second"{
	err:=ipt.Delete("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/second",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
	if err !=nil{
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.RATE=="min"{
		err:=ipt.Delete("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/min",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	if req.RATE=="hour"{
		err:=ipt.Delete("filter","INPUT","-s",req.IP,"-m","state","--state","NEW","-m","limit","--limit",fmt.Sprintf("%d/hour",req.NUMBER),"--limit-burst","100","-j","ACCEPT")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	return c.JSON(200,map[string]string{"message":"ip blocking success"})
}
func getRules(c echo.Context) error{
	table:="filter"
	rules1,err:=ipt.List(table,"INPUT")
	if err!=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Unable to get the current rules list"})
	}
	rules2,err:=ipt.List(table,"OUTPUT")
	if err!=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Unable to get the current rules list"})
	}
	rules:=append(rules1,rules2...)
	return c.JSON(200,map[string]interface{}{
		"table":table,
		"chain":"INPUT",
		"rules":rules,
	})
}
func blockIP(c echo.Context) error{
	type BlockIP struct{
		IP string `json:"ip"`
		TYPE string `json:"type"`
	}
	req:= new(BlockIP)
	if err:=c.Bind(req); err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	//check if ip address is valid
	ip:=net.ParseIP(req.IP)
	if ip==nil{
		return c.JSON(400,map[string]string{"error":"Invalid IP address"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	fmt.Println(req.TYPE)
	//add new rule to block that IP
	if req.TYPE=="incoming"{
	err:=ipt.AppendUnique("filter","INPUT","-s",req.IP,"-j","DROP")
	if err !=nil{
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-s",req.IP,"-j","DROP")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		}
	
	return c.JSON(200,map[string]string{"message":"ip blocking success"})
}
func unblockIP(c echo.Context) error{
	type UNBlockIP struct{
		IP string `json:"ip"`
		TYPE string `json:"type"`
	}
	req:= new(UNBlockIP)
	if err:=c.Bind(req); err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	//check if ip address is valid
	ip:=net.ParseIP(req.IP)
	if ip==nil{
		return c.JSON(400,map[string]string{"error":"Invalid IP address"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.TYPE=="incoming"{
	//delete the rule
	err:=ipt.Delete("filter","INPUT","-s",req.IP,"-j","DROP")
	if err !=nil{
		return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		//delete the rule
		err:=ipt.Delete("filter","OUTPUT","-s",req.IP,"-j","DROP")
		if err !=nil{
			return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
		}
		}
	return c.JSON(200,map[string]string{"message":"ip unblocking success"})
}

func blockPort(c echo.Context) error{
	type BlockPort struct{
		Port int `json:"port"`
		Protocol string `json:"protocol"`
		TYPE string `json:"type"`
	}
	req:= new(BlockPort)
	if err:=c.Bind(req); err!=nil{
		fmt.Println(err)
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.Protocol!="tcp" && req.Protocol!="udp" && req.Protocol!="both"{
		return c.JSON(400,map[string]string{"error":"Invalid Protocol. It can be tcp,udp or both"})
	}
	if(req.Protocol=="tcp"){
		if req.TYPE=="incoming"{
		err:=ipt.AppendUnique("filter","INPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	}else if (req.Protocol=="udp"){
		if req.TYPE=="incoming"{
		err:=ipt.AppendUnique("filter","INPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
	if err !=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
	if err !=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	}else if(req.Protocol=="both"){
		if req.TYPE=="incoming"{
		err:=ipt.AppendUnique("filter","INPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		err=ipt.AppendUnique("filter","INPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		err=ipt.AppendUnique("filter","OUTPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
	}
	}else{
		return c.JSON(500,map[string]string{"error":"Failed to add the rule, Unknown protocol"})
	}
	//add the rule to block port
	
	return c.JSON(200,map[string]string{"message":"port blocking success"})
}

func unblockPort(c echo.Context) error{
	type BlockPort1 struct{
		Port int `json:"port"`
		Protocol string `json:"protocol"`
		TYPE string `json:"type"`
	}
	req:= new(BlockPort1)
	if err:=c.Bind(req); err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if(req.Protocol=="tcp"){
		if req.TYPE=="incoming"{
	//add the rule to block port
	err:=ipt.Delete("filter","INPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
	if err !=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
	}
}
if req.TYPE=="outgoing"{
	//add the rule to block port
	err:=ipt.Delete("filter","OUTPUT","-p","tcp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
	if err !=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
	}
}
	}
	if(req.Protocol=="udp"){
		if req.TYPE=="incoming"{
		//add the rule to block port
		err:=ipt.Delete("filter","INPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
		}
	}
	if req.TYPE=="outgoing"{
		//add the rule to block port
		err:=ipt.Delete("filter","OUTPUT","-p","udp","--dport",fmt.Sprintf("%d",req.Port),"-j","DROP")
		if err !=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
		}
	}
		}
	return c.JSON(200,map[string]string{"message":"port unblocking success"})
}

func blockProtocol(c echo.Context) error{
	type BlockProtocol struct{
		Protocol string `json:"protocol"`
		TYPE string `json:"type"`
	}
	req:=new(BlockProtocol)
	if err:=c.Bind(req);err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.TYPE == "incoming"{
	err:=ipt.AppendUnique("filter","INPUT","-p",req.Protocol,"-j","DROP")
	if err!=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.TYPE == "outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-p",req.Protocol,"-j","DROP")
		if err!=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		}
	return c.JSON(200,map[string]string{"message":"protocol blocking success"})
}
func unblockProtocol(c echo.Context) error{
	type UNBlockProtocol struct{
		Protocol string `json:"protocol"`
		TYPE string `json:"type"`
	}
	req:=new(UNBlockProtocol)
	if err:=c.Bind(req);err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.TYPE=="incoming"{
		err:=ipt.Delete("filter","INPUT","-p",req.Protocol,"-j","DROP")
	if err!=nil{
		return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.Delete("filter","OUTPUT","-p",req.Protocol,"-j","DROP")
	if err!=nil{
		return c.JSON(500,map[string]string{"error":"Failed to delete the rule"})
	}
	}
	return c.JSON(200,map[string]string{"message":"protocol unblocking success"})
}
func blockCountry(c echo.Context) error{
	type BlockCountry struct{
		Country string `json:"country"`
		TYPE string `json:"type"`
	}
	req:=new(BlockCountry)
	if err:=c.Bind(req);err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.TYPE=="incoming"{
	err:=ipt.AppendUnique("filter","INPUT","-m","geoip","--src-cc",req.Country,"-j","DROP")
	if err!=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.AppendUnique("filter","OUTPUT","-m","geoip","--src-cc",req.Country,"-j","DROP")
		if err!=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		}
	return c.JSON(200,map[string]string{"message":"country blocking success"})
}
func unblockCountry(c echo.Context) error{
	type BlockCountry struct{
		Country string `json:"country"`
		TYPE string `json:"type"`
	}
	req:=new(BlockCountry)
	if err:=c.Bind(req);err!=nil{
		return c.JSON(400,map[string]string{"error":"Invalid Request"})
	}
	if req.TYPE!="incoming" && req.TYPE!="outgoing"{
		return c.JSON(400,map[string]string{"error":"Invalid Blocking Type. It can be incoming or outgoing"})
	}
	if req.TYPE=="incoming"{
	err:=ipt.Delete("filter","INPUT","-m","geoip","--src-cc",req.Country,"-j","DROP")
	if err!=nil{
		fmt.Println(err)
		return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
	}
	}
	if req.TYPE=="outgoing"{
		err:=ipt.Delete("filter","OUTPUT","-m","geoip","--src-cc",req.Country,"-j","DROP")
		if err!=nil{
			fmt.Println(err)
			return c.JSON(500,map[string]string{"error":"Failed to add the rule"})
		}
		}
	return c.JSON(200,map[string]string{"message":"country blocking success"})
}
func getLogs(c echo.Context) error{
	blockedTraffic,err :=getBlockedTraffic()
	if err!=nil{
		return c.JSON(500,map[string]string{"error":"Failed to retrieve the logs"})
	}
	return c.JSON(200,blockedTraffic)
}
func getBlockedTraffic() ([]BlockedLog,error){
	cmd:=exec.Command("grep","DROP:",syslogPath)
	output,err:=cmd.CombinedOutput()
	if err!=nil{
		fmt.Printf("Error getting the logs: %v\n",err)
		return nil,err
	}
	lines:=strings.Split(string(output),"\n")
	var blockedTraffic []BlockedLog
	for _,line:=range lines{
		fmt.Println(line)
		logEntry,err:=parseLogEntry(line)
		if err !=nil{
			continue
		}
		blockedTraffic=append(blockedTraffic, logEntry)
	}
	return blockedTraffic,nil
}
//TODO
func parseLogEntry(logLine string)(BlockedLog,error){
	fields:= strings.Fields(logLine)
	if(len(fields)<4){
		return BlockedLog{},nil
	}
	timestamps := fmt.Sprintf("%s %s %s",fields[0],fields[1],fields[2])
	timestamp,err:=time.Parse("Jan 2 15:14:05",timestamps)
	if err!=nil{
		return BlockedLog{},nil
	}
	sourceIP:=fields[3]
	destinationIP:=fields[4]
	blockedReason:="Blocked by iptables rule"
	logEntry:=BlockedLog{
		Timestamp: timestamp,
		SourceIP: sourceIP,
		DestinationIP: destinationIP,
		BlockedReason: blockedReason,
	}
	return logEntry,nil
}
