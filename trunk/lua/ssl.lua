local lxyssl = require 'lxyssl'
local socket = require 'socket'
local bufferio = require 'bufferio'
local url = require("socket.url")
local http = require("socket.http")
local ltn12 = require("ltn12")
local setmetatable = setmetatable
local getmetatable = getmetatable
local rawget = rawget
local type=type
local print=print
local ipairs=ipairs
local pairs=pairs
local tconcat=table.concat
local tostring=tostring
local select = select
local unpack=unpack
local assert=assert
local string=string
module ('ssl')

async_timeout = 0
trace=0
untrusted_ssl=false

local function proto_index(o, k)  
    local p = rawget(o, '__proto')
    if not p then return end
    local v = p[k]
    if type(v) == "function" then return function(x,...) return v(o.__proto,...) end 
    else return v end
end

local function prototype(o)
    return setmetatable({__proto=o}, {__index = proto_index, __tostring=function(self) return "ssl ojbect:" .. tostring(self._proto) end })
end

local function prototypeX(p,o)
  local o= o or {}
  o.__proto = p
  local proto = getmetatable(p)
  if not proto then proto = p else proto = proto.__index end
  for k,v in pairs(proto) do
    if type(v) == 'function' then o[k] = function(self, ...) return v(self.__proto, ...) end end
  end
  return o
end

local blank={}
local sessions=setmetatable({},{__mode="v"}) --index by session id, weak value effectively a cache
local custom_session_manager=setmetatable({},{__mode="k"}) --indexed by xyssl object

do
  local m = getmetatable(lxyssl.ssl())
  m.get_session = function(x, id, cipher)
    local sm = custom_session_manager[x]
    if sm and sm.get_session then return sm.get_session(x, id, cipher) end
    local s = sessions[id]
    if s and s.cipher == cipher then return s.master end
  end
  m.set_session = function(x, id, cipher, master)
    local sm = custom_session_manager[x]
    if sm and sm.set_session then return sm.set_session(x, id, cipher, master) end
    sessions[id] = {cipher=cipher, master=master}
  end
end

local function close(self)
  if copas and copas.release then 
    copas.release(self.__wrapped) 
    copas.release(self.__ssl) 
    copas.release(self.__proto) 
  end
  if self.__ssl then self.__ssl:close() end
  if self.__proto then self.__proto:close() end
end

local function connect(self,...)
  if not self.__proto then return nil, self._last_err end
  self.__proto:setoption('tcp-nodelay',true)
  local r, e = copas and copas.connect(self.__proto, ...) or self.__proto:connect(...)
  if not e then
    if self.ssl then
      local x = lxyssl.ssl()  -- SSL client object by default
      local b = bufferio.wrap(x)
      local host = select(1,...)
      if trace then x:debug(trace) end
      x:connect(self:getfd())
      x:authmode(x:hasca() and not untrusted_ssl and 2 or 1, host) --by default, verify
      self.__ssl = x
      self.__wrapped = b
      if copas then 
        x:settimeout(async_timeout) 
        self.send = function(self, ...) return copas.send(self.__wrapped,...) end
        self.receive = function(self, ...) return copas.receive(self.__wrapped,...) end
      else 
        x:settimeout() 
        self.send = function(self, ...) return b:send(...) end
        self.receive = function(self, ...) return b:receive(...) end
      end
    else
      if copas then
        self.__proto:settimeout(async_timeout) 
        --if true then return copas.wrap(self.__proto) end
        self.send = function(self, ...) return copas.send(self.__proto,...) end
        self.receive = function(self, ...) return copas.receive(self.__proto,...) end
      else
        self.__proto:settimeout() 
      end
    end
    return 1
  end
  return r, e or "connect refused",""
end

local function settimeout(self, t)
 if not self.__proto then return nil, self._last_err end
 self.timeout = t
 return (self.__ssl or self.__proto):settimeout(t)
end

local function gettimeout(self, t)
 self.timeout = t
 return 1
end

function async(dispatcher)
  copas = dispatcher
end

local function set_session_manager(o, get_session, set_session)
  custom_session_manager[o.__ssl] = {get_session=get_session, set_session=set_session}
end

local function stream_close(stream)
  if stream.__ssl then stream.__ssl:close() end
  if stream.__skt then stream.__skt:close() end
end

function stream(sock, params)
  params = params or {}
  --this function should be used to turn normal socket into ssl stream
  --for the possibility of being subsituted with alternative library(like luaclr which is C# only)
  --sock is a connected socket
  --params is table with the following key
    --close a flag indicate if the underlying socket should be closed if the ssl stream is closed
    --auth  is a callback function to determine if security policy is allowed
    --certkey is a callback function to retrieve the x509 cert/key to use(if there is multiple)
    --server  indicate if this stream is for client or server(as the handshaking is different)
    --host remove host for certificate verification
    --ca CAs in PEM format
  local x = lxyssl.ssl(params.server)
  local y = bufferio.wrap(x) --provided operation that is luasocket/lua io compatable
  if params.server or params.certkey then 
    --setup cert either provided or embedded if this is a server(a must)
    x:certkey(params.certkey and params.certkey()) 
  end 
  if params.ca then x:setca(params.ca) end
  if (params.host and x:hasca()) or params.verify then x:authmode(params.verify or 2, params.host) end
  x:connect(sock:getfd())
  y.__skt = sock -- lock down the socket object, just in case the wrapper doesn't
  y.__ssl = x -- lock down the lxyssl object, just in case the wrapper does't
  y.close = stream_close -- override the close
  y.set_session_manager = set_session_manager -- allows for session manager override
  return y
end

function request(reqt, b)
  if type(reqt) == "string" then
    local t = {}
    local reqt = {
        url = reqt,
        sink = ltn12.sink.table(t),
        create = tcp,
    }
    if b then
        reqt.source = ltn12.source.string(b)
        reqt.headers = {
            ["content-length"] = string.len(b),
            ["content-type"] = "application/x-www-form-urlencoded"
        }
        reqt.method = "POST"
    end
    local code, headers, status = socket.skip(1, http.request(reqt))
    return tconcat(t), code, headers, status
  else
    local nreqt = {}
    for k,v in pairs(reqt) do nreqt[k]= v end
    nreqt.create = reqt.create or tcp
    return http.request(nreqt) 
  end
end

function tcp(scheme)
  local s,e = socket.tcp()
  if not copas and scheme ~= "https" then return s end
  local o = prototype(s)
  o.connect = connect
  o.settimeout = settimeout
  o.gettimeout = gettimeout
  o.close = close
  o.ssl = scheme == "https"
  o._last_err = e
  return o
end

function clearca()
  return lxyssl.clearca()
end

function addca(ca_pem)
  local r = lxyssl.addca(ca_pem)
  return r 
end
