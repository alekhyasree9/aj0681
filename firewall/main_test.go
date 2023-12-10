package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
)

func TestLoginValidCredentials(t *testing.T) {
	payload:=[]byte(`{"username":"admin","password":"admin1"}`)
	req:=httptest.NewRequest(http.MethodPost,"/login",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,login(c))
	assert.Equal(t,http.StatusOK,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"token")
}
func TestLoginInValidCredentials1(t *testing.T) {
	payload:=[]byte(`{"username":"admin","password":"admin"}`)
	req:=httptest.NewRequest(http.MethodPost,"/login",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,login(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestLoginInValidCredentials2(t *testing.T) {
	payload:=[]byte(`{"username":"","password":"admin1"}`)
	req:=httptest.NewRequest(http.MethodPost,"/login",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,login(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestLoginInValidCredentials3(t *testing.T) {
	payload:=[]byte(`{"username":"admin","password":""}`)
	req:=httptest.NewRequest(http.MethodPost,"/login",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,login(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestLoginInValidCredentials4(t *testing.T) {
	payload:=[]byte(`{"username":"","password":""}`)
	req:=httptest.NewRequest(http.MethodPost,"/login",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,login(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockIPINValidIP1(t *testing.T) {
	payload:=[]byte(`{"ip":"192.168.1","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockIPINValidIP2(t *testing.T) {
	payload:=[]byte(`{"ip":"256.256.256.256","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockIPINValidType(t *testing.T) {
	payload:=[]byte(`{"ip":"192.168.1.1","type":"something"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockIPINValidIP1(t *testing.T) {
	payload:=[]byte(`{"ip":"192.168.1","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockIPINValidIP2(t *testing.T) {
	payload:=[]byte(`{"ip":"256.256.256.256","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockIPINValidType(t *testing.T) {
	payload:=[]byte(`{"ip":"192.168.1.1","type":"something"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/ip",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockIP(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockPortINValidPort1(t *testing.T) {
	payload:=[]byte(`{"port":"-250","protocol","tcp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockPortINValidPort2(t *testing.T) {
	payload:=[]byte(`{"port":"999999999999","protocol","tcp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockPortINValidprotocol(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","snmp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockPortINValidprotocol2(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockPortINValidtype(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","tcp","type":"something"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockPortINValid(t *testing.T) {
	payload:=[]byte(`{"port":"","protocol","","type":""}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValidPort1(t *testing.T) {
	payload:=[]byte(`{"port":"-250","protocol","tcp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValidPort2(t *testing.T) {
	payload:=[]byte(`{"port":"999999999999","protocol","tcp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValidprotocol(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","snmp","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValidprotocol2(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","","type":"incoming"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValidtype(t *testing.T) {
	payload:=[]byte(`{"port":"80","protocol","tcp","type":"something"}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockPortINValid(t *testing.T) {
	payload:=[]byte(`{"port":"","protocol","","type":""}`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/port",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockPort(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestStatisticsOut(t *testing.T) {
	req:=httptest.NewRequest(http.MethodGet,"/getStatisticsout",nil)
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,getStatisticsout(c))
	assert.Equal(t,http.StatusOK,rec.Code)
}
func TestStatisticsIn(t *testing.T) {
	req:=httptest.NewRequest(http.MethodGet,"/getStatisticsin",nil)
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,getStatisticsin(c))
	assert.Equal(t,http.StatusOK,rec.Code)
}

func TestBlockLimitRateINValidIP1(t *testing.T) {
	payload:=[]byte(`{"ip":"0.0.0.0.0","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockLimitRateINValidIP2(t *testing.T) {
	payload:=[]byte(`{"ip":"","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidIP3(t *testing.T) {
	payload:=[]byte(`{"ip":"256.0.0.0","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidrate1(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockLimitRateINValidrate2(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min1","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidnumber4(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"second","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidnumber5(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"min","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidnumber6(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"hour","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidnumber4(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"second","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidnumber5(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"min","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidnumber6(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.0","rate":"hour","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockLimitRateINValidnumber1(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":"5"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockLimitRateINValidnumber2(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockLimitRateINValidnumber3(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":999999999999999`)
	req:=httptest.NewRequest(http.MethodPost,"/block/limitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockLimitRateINValidIP1(t *testing.T) {
	payload:=[]byte(`{"ip":"0.0.0.0.0","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockLimitRateINValidIP2(t *testing.T) {
	payload:=[]byte(`{"ip":"","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidIP3(t *testing.T) {
	payload:=[]byte(`{"ip":"256.0.0.0","rate":"min","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidrate1(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockLimitRateINValidrate2(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min1","number":5}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockLimitRateINValidnumber1(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":"5"}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockLimitRateINValidnumber2(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":}`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockLimitRateINValidnumber3(t *testing.T) {
	payload:=[]byte(`{"ip":"10.0.0.1","rate":"min","number":999999999999999`)
	req:=httptest.NewRequest(http.MethodPost,"/block/unblocklimitrate",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockLimitRate(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}


func TestBlockProtocolINvalidProtocol(t *testing.T) {
	payload:=[]byte(`{"protocol":"http","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockProtocolINvalidProtocol1(t *testing.T) {
	payload:=[]byte(`{"protocol":"","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockProtocolINvalidtype1(t *testing.T) {
	payload:=[]byte(`{"protocol":"tcp","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/block/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockProtocolINvalidtype2(t *testing.T) {
	payload:=[]byte(`{"protocol":"tcp","type":"something"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockProtocolINvalidProtocol(t *testing.T) {
	payload:=[]byte(`{"protocol":"http","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockProtocolINvalidProtocol1(t *testing.T) {
	payload:=[]byte(`{"protocol":"","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockProtocolINvalidtype1(t *testing.T) {
	payload:=[]byte(`{"protocol":"tcp","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockProtocolINvalidtype2(t *testing.T) {
	payload:=[]byte(`{"protocol":"tcp","type":"something"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/protocol",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockProtocol(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockCountryInvalidCountry(t *testing.T) {
	payload:=[]byte(`{"country":"tcp","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockCountryInvalidCountry1(t *testing.T) {
	payload:=[]byte(`{"country":"","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestBlockCountryInvalidtype1(t *testing.T) {
	payload:=[]byte(`{"country":"CA","type":"something"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockCountryInvalidtype2(t *testing.T) {
	payload:=[]byte(`{"country":"CA","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockCountryInvalidboth(t *testing.T) {
	payload:=[]byte(`{"country":"CA1","type":"yes"`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestBlockCountryInvalidboth2(t *testing.T) {
	payload:=[]byte(`{"country":"","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/block/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,blockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockCountryInvalidCountry(t *testing.T) {
	payload:=[]byte(`{"country":"tcp","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockCountryInvalidCountry1(t *testing.T) {
	payload:=[]byte(`{"country":"","type":"incoming"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}

func TestUnBlockCountryInvalidtype1(t *testing.T) {
	payload:=[]byte(`{"country":"CA","type":"something"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockCountryInvalidtype2(t *testing.T) {
	payload:=[]byte(`{"country":"CA","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockCountryInvalidboth(t *testing.T) {
	payload:=[]byte(`{"country":"CA1","type":"yes"`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}
func TestUnBlockCountryInvalidboth2(t *testing.T) {
	payload:=[]byte(`{"country":"","type":""`)
	req:=httptest.NewRequest(http.MethodPost,"/unblock/country",bytes.NewBuffer(payload))
	req.Header.Set("Content-Type","application/json")
	rec:=httptest.NewRecorder()
	e:=echo.New()
	q:=make(url.Values)
	q.Set("Content-Type","application/json")
	c:=e.NewContext(req,rec)
	assert.NoError(t,unblockCountry(c))
	assert.Equal(t,http.StatusBadRequest,rec.Code)
	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(),&response)
	assert.Contains(t,response,"error")
}