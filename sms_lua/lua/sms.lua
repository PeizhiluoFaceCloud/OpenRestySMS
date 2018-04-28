#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

-----------------代码规范说明-----------------
--[[
所有程序基本框架都是类似的
说明1>对错误应答的处理
	在processmsg函数中会调用各个处理分支，如果分支函数成功则其内部返回http应答
	如果返回失败，由processmsg判断返回值统一应答
说明2>对鉴权等常规共性的动作做好可以统一到脚本中去执行
说明3>HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
]]

--[设定搜索路径]
--将自定义包路径加入package的搜索路径中。也可以加到环境变量LUA_PATH中
--放到init_lus_path.lua中，不然的话，每一个请求处理的时候都会对全局变量
--package.path进行设置，导致

--[包含公共的模块]
local tableutils = require("common_lua.tableutils")		--打印工具
local cjson = require("cjson.safe")
local wanip_iresty = require("common_lua.wanip_iresty")
local http_iresty = require ("resty.http")
local redis_iresty = require("common_lua.redis_iresty")
local script_utils = require("common_lua.script_utils")

--[基本变量参数]
local redis_ip = nil
local redis_port = 6379
local AccessKeyId = nil
local AccessKeySecret = nil
local SignName = nil
local TemplateCode = nil

--发送应答数据报
function send_resp_table (status,resp)
	if not resp or type(resp) ~= "table" then
		ngx.log(ngx.ERR, "send_resp_table:type(resp) ~= table", type(resp))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local resp_str = cjson.encode(resp)
	--ngx.log(ngx.NOTICE, "send_resp_table:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end
function send_resp_string(status,message_type,error_string)
	if not message_type or type(message_type) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(message_type) ~= string", type(message_type))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	if not error_string or type(error_string) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(error_string) ~= string", type(error_string))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = message_type
	jrsp["DDIP"]["Header"]["ErrorNum"] = string.format("%d",status)
	jrsp["DDIP"]["Header"]["ErrorString"] = error_string
	local resp_str = cjson.encode(jrsp)
	--ngx.log(ngx.NOTICE, "send_resp_string:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end

--对输入的参数做有效性检查，返回解码后的消息体对象json对象
function get_request_param()
	--ngx.log(ngx.NOTICE, "get_request_param:",ngx.var.request_body)
    local req_body, err = cjson.decode(ngx.var.request_body)
	if not req_body then
		ngx.log(ngx.ERR, "get_request_param:req body is not a json")
		return nil, "req body is not a json"
    end
    if not req_body["DDIP"]
        or not req_body["DDIP"]["Header"]
        or not req_body["DDIP"]["Header"]["Version"]
        or not req_body["DDIP"]["Header"]["CSeq"]
        or not req_body["DDIP"]["Header"]["MessageType"]
        or not req_body["DDIP"]["Body"]
        or type(req_body["DDIP"]["Header"]["Version"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["CSeq"]) ~= "string"
        or type(req_body["DDIP"]["Header"]["MessageType"]) ~= "string"
		then
        ngx.log(ngx.ERR, "invalid args")
        return nil, "invalid protocol format args"
    end
    return req_body, "success"
end

--创建一个随机数
local function get_random_authcode()
	--math.randomseed(os.time())
	return string.format("%06d",math.random(1000000))
end

--创建uuid
local function get_SignatureNonce()
	--math.randomseed(os.time())
	return string.format("45e25e9b-%04x-%04x-%04x-2956eda1b466",math.random(10000),math.random(10000),math.random(10000))
end

--从日期字符串中截取出年月日时分秒[0000-00-00 00:00:00]
local function string2time(timeString)  
    local Y = string.sub(timeString,1,4)  
    local M = string.sub(timeString,6,7)  
    local D = string.sub(timeString,9,10)  
    local H = string.sub(timeString,12,13)  
    local MM = string.sub(timeString,15,16)  
    local SS = string.sub(timeString,18,19)
    return os.time{year=Y,month=M, day=D, hour=H,min=MM,sec=SS}  
end
 
local function specialUrlEncode(value)
    --常规的url编码
    local encodeUrl = string.sub(ngx.encode_args({a = value}),3)     --去掉"a="
    
    --注意 string.gsub调用之后返回 两个值,一个是替换后的字符串,第二个是替换的次数。 
    --而一旦外面加了括号,就只返回第一个值,即替换后的字符串。
    return (string.gsub((string.gsub((string.gsub(encodeUrl,"+", "%20")),"*", "%2A")),"~","%7E"))
end

local function sign(sk,stringToSign)
	return ngx.encode_base64(ngx.hmac_sha1(sk,stringToSign))
end

--向第三方短信服务发送请求
local function send_sms(PhoneNumbers,authcode)
    --阿里短信服务域名
    local sms_domain = "dysmsapi.aliyuncs.com"
    --解释一下的域名
	local host_ip,err = wanip_iresty.getdomainip(sms_domain)
	if not host_ip then
        ngx.log(ngx.ERR,"getdomainip failed ",err,sms_domain)
        return false,"getdomainip failed"
    end
    
    --对比调试用
    --[[
    local SignatureNonce =  "45e25e9b-0a6f-4070-8c85-2956eda1b466"
    local Timestamp = "2017-07-12T02:42:19Z"
    local AccessKeyId = "testId"
    local AccessKeySecret = "testSecret";
    local PhoneNumbers = "15300000001"
    local SignName = "阿里云短信测试专用"
    local TemplateCode = "SMS_71390007"   
    local TemplateParam = "{\"customer\":\"test\"}"
    ]]    

    --生产用
    local SignatureNonce = get_SignatureNonce()
    local Timestamp = (string.gsub(ngx.utctime()," ", "T")).."Z"
    local TemplateParam = "{\"code\":\""..authcode.."\"}"
    print("AccessKeyId--->",AccessKeyId)
    print("AccessKeySecret--->",AccessKeySecret)
    print("PhoneNumbers--->",PhoneNumbers)
    print("SignName--->",SignName)
    print("TemplateCode--->",TemplateCode)
    print("TemplateParam--->",TemplateParam)

    --字符串(编码前)
    --[[local sortQueryString = 
        specialUrlEncode("AccessKeyId").."="..specialUrlEncode(AccessKeyId)
        .."&"..specialUrlEncode("Action").."="..specialUrlEncode("SendSms")
        .."&"..specialUrlEncode("Format").."="..specialUrlEncode("XML")
        .."&"..specialUrlEncode("OutId").."="..specialUrlEncode("123")
        .."&"..specialUrlEncode("PhoneNumbers").."="..specialUrlEncode(PhoneNumbers)
        .."&"..specialUrlEncode("RegionId").."="..specialUrlEncode("cn-hangzhou")
        .."&"..specialUrlEncode("SignName").."="..specialUrlEncode(SignName)
        .."&"..specialUrlEncode("SignatureMethod").."="..specialUrlEncode("HMAC-SHA1")
        .."&"..specialUrlEncode("SignatureNonce").."="..specialUrlEncode(SignatureNonce)
        .."&"..specialUrlEncode("SignatureVersion").."="..specialUrlEncode("1.0")
        .."&"..specialUrlEncode("TemplateCode").."="..specialUrlEncode(TemplateCode)
        .."&"..specialUrlEncode("TemplateParam").."="..specialUrlEncode(TemplateParam)
        .."&"..specialUrlEncode("Timestamp").."="..specialUrlEncode(Timestamp)
        .."&"..specialUrlEncode("Version").."="..specialUrlEncode("2017-05-25")]]
    local sortQueryString = 
        specialUrlEncode("AccessKeyId").."="..specialUrlEncode(AccessKeyId)
        .."&"..specialUrlEncode("Action").."="..specialUrlEncode("SendSms")
        .."&"..specialUrlEncode("PhoneNumbers").."="..specialUrlEncode(PhoneNumbers)
        .."&"..specialUrlEncode("RegionId").."="..specialUrlEncode("cn-hangzhou")
        .."&"..specialUrlEncode("SignName").."="..specialUrlEncode(SignName)
        .."&"..specialUrlEncode("SignatureMethod").."="..specialUrlEncode("HMAC-SHA1")
        .."&"..specialUrlEncode("SignatureNonce").."="..specialUrlEncode(SignatureNonce)
        .."&"..specialUrlEncode("SignatureVersion").."="..specialUrlEncode("1.0")
        .."&"..specialUrlEncode("TemplateCode").."="..specialUrlEncode(TemplateCode)
        .."&"..specialUrlEncode("TemplateParam").."="..specialUrlEncode(TemplateParam)
        .."&"..specialUrlEncode("Timestamp").."="..specialUrlEncode(Timestamp)
        .."&"..specialUrlEncode("Version").."="..specialUrlEncode("2017-05-25")
    print("sortQueryString------>:",sortQueryString)
    
    --待签名的字符串
    local stringToSign = "GET&%2F&"..specialUrlEncode(sortQueryString)
    print("stringToSign------>:",stringToSign)
    
    --签名操作
    local signStr = sign(AccessKeySecret.."&", stringToSign)
    print("signStr------>:",signStr)
    local Signature = specialUrlEncode(signStr)
    print("Signature------>:",Signature)
    
    --向短信服务器发布请求
    local httpc = http_iresty.new()
    httpc:set_timeout(3000)
	local ok, err = httpc:connect(host_ip,80)
	if not ok  then
		ngx.log(ngx.ERR,"httpc:connect failed ",host_ip,err)
		return false,"httpc:connect failed "..host_ip
	end
	local res, err = httpc:request{
		method = "GET",
		path = "/?Signature="..Signature.."&"..sortQueryString,
		headers = {
                ["Host"] = sms_domain,
                },
        }
    if not res  then
		ngx.log(ngx.ERR,"request,failed to request: ", err)
		return false,"request,failed to request"..err
	end
	--[[
    if res.status ~= ngx.HTTP_OK then
		ngx.log(ngx.ERR,"res.status is unexpected",res.status)
        return false,"res.status is unexpected"
	end
    ]]
    local body =res:read_body()
    if( nil == string.find(body,"<Code>OK</Code>"))then
        ngx.log(ngx.ERR,"Sms Response Error:",body)
        return false,"Sms Response Error"
    end
	return true
end

--处理注册消息
function do_sms(jreq)
	--判断命令格式的有效性
	if not jreq["DDIP"]["Body"]["Project"]
		or not jreq["DDIP"]["Body"]["PhoneNumber"]
		or type(jreq["DDIP"]["Body"]["Project"]) ~= "string"
        or type(jreq["DDIP"]["Body"]["PhoneNumber"]) ~= "string"
		then
	    ngx.log(ngx.ERR, "do_sms invalid args")
	    return false,"do_sms invalid args"
	end

    --创建redis操作句柄
    local opt = {["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3}
	local red_handler = redis_iresty:new(opt)
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new red_handler failed")
		return false,"redis_iresty:new red_handler failed"
	end
    --获取项目信息(验证一下,项目是否存在，以及是否在有效期内)
    local project_key = "project:"..jreq["DDIP"]["Body"]["Project"]..":info"
    local project_info, err = red_handler:hmget(project_key,"RegisterBegin","RegisterEnd")
    if not project_info then
	    ngx.log(ngx.ERR, "get project info failed : ", project_key,err,redis_ip)
		return false,"get project info failed"
	end
    --返回的排列顺序(key1,val1,key2,val2,key3,val3)，下标从1开始
    local RegisterBegin = string2time(project_info[1])
    local RegisterEnd = string2time(project_info[2])
    if(os.time() < RegisterBegin) then
        ngx.log(ngx.ERR, "check reigster begin time failed:",os.date("%Y-%m-%d %H:%M:%S"),project_info[1])
		return false,"check reigster begin time failed:"
    end
    if(os.time() > RegisterEnd) then
        ngx.log(ngx.ERR, "check reigster end time failed:",os.date("%Y-%m-%d %H:%M:%S"),project_info[2])
		return false,"check reigster end time failed:"
    end
    
    --先确认一下授权码的发送频率
    --(1分钟发送一条,5分钟的生命周期)
    local authcode_key = "project:"..jreq["DDIP"]["Body"]["Project"]..":sms:"..jreq["DDIP"]["Body"]["PhoneNumber"]
    local ok = red_handler:ttl(authcode_key)
    if ok > 240 then
	    ngx.log(ngx.ERR, "authcode request too fast")
		return false,"authcode request too fast"
	end

    --随机产生一个授权码
    local authcode_val = get_random_authcode()    
    ------------对接第三方短信服务------------
    local ret = send_sms(jreq["DDIP"]["Body"]["PhoneNumber"],authcode_val)
    if ret ~= true then
        ngx.log(ngx.ERR, "send_sms failed")
        return false,"send_sms failed"
    end

    --把授权码写入到数据库中
	local ok, err = red_handler:set(authcode_key,authcode_val)
    if not ok then
	    ngx.log(ngx.ERR, "set authcode to redis failed")
		return false,"set authcode to redis failed"
	end
    local ok, err = red_handler:expire(authcode_key,300) --TTL=5分钟的生命周期
    if not ok then
	    ngx.log(ngx.ERR, "expire authcode to redis failed")
		return false,"expire authcode to redis failed"
	end

    --返回应答数据
	local jrsp = {}
	jrsp["DDIP"] = {}
	jrsp["DDIP"]["Header"] = {}
	jrsp["DDIP"]["Header"]["Version"] = "1.0"
	jrsp["DDIP"]["Header"]["CSeq"] = "1"
	jrsp["DDIP"]["Header"]["MessageType"] = "MSG_AUTHCODE_RSP"
	jrsp["DDIP"]["Header"]["ErrorNum"] = "200"
	jrsp["DDIP"]["Header"]["ErrorString"] = "Success OK"
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

--消息处理函数入库
function process_msg()
	--获取请求对象
	local jreq, err = get_request_param()
	if not jreq then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end
	--分命令处理
	if(jreq["DDIP"]["Header"]["MessageType"] == "MSG_AUTHCODE_REQ") then
		local ok, err = do_sms(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_AUTHCODE_RSP",err);
		end
	else
		ngx.log(ngx.ERR, "invalid MessageType",jreq["DDIP"]["Header"]["MessageType"])
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any","invalid MessageType");
	end
	return
end

--加载配置信息(环境变量中配置)
local function load_config_info()
    --数据库地址
    redis_ip = ngx.shared.shared_data:get("RedisIP")
	if redis_ip == nil  then
		ngx.log(ngx.ERR,"get RedisIP failed ")
        return false
	end
	--配置信息
    AccessKeyId = ngx.shared.shared_data:get("AccessKeyId")
	if AccessKeyId == nil  then
		ngx.log(ngx.ERR,"get AccessKeyId failed ")
        return false
	end
	AccessKeySecret = ngx.shared.shared_data:get("AccessKeySecret")
	if AccessKeySecret == nil  then
		ngx.log(ngx.ERR,"get AccessKeySecret failed ")
        return false
	end
	SignName = ngx.shared.shared_data:get("SignName")
	if SignName == nil  then
		ngx.log(ngx.ERR,"get SignName failed ")
        return false
	end
	TemplateCode = ngx.shared.shared_data:get("TemplateCode")
	if TemplateCode == nil  then
		ngx.log(ngx.ERR,"get TemplateCode failed ")
        return false
	end
	return true
end

--程序入口
--print("get request_body:"..ngx.var.request_body)
--print("=====================new request=======================\n")
--print("get server_port::::",ngx.var.server_port,type(ngx.var.server_port))
if(ngx.var.server_port == "8002") then			-->sms.xxxxxx.xxxx:8002
	local ok = load_config_info()
	if not ok then
		ngx.log(ngx.ERR,"load_config_info failed ")
		return false
	end
else
	ngx.log(ngx.ERR,"invlaid ngx.var.server_port",ngx.var.server_port)
	return false
end
process_msg()
