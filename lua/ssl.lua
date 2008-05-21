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
debug=0

local function proto_index(o, k)  
    local p = rawget(o, '__proto')
    if not p then return end
    local v = p[k]
    if type(v) == "function" then return function(x,...) return v(o.__proto,...) end 
    else return v end
end

local function prototype(o)
    return setmetatable({__proto=o}, {__index = proto_index })
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

local function close(self)
  if copas and copas.release then 
    copas.release(self.__wrapped) 
    copas.release(self.__ssl) 
    copas.release(self.__proto) 
  end
end

local function connect(self,...)
  if not self.__proto then return nil, self._last_err end
  self.__proto:setoption('tcp-nodelay',true)
  local r, e = copas and copas.connect(self.__proto, ...) or self.__proto:connect(...)
  if not e then
    if self.ssl then
      local x = lxyssl.ssl(0)  -- SSL client object
      local b = bufferio.wrap(x)
      if debug then x:debug(debug) end
      x:connect(self:getfd())
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

function stream(sock, close, auth, keycert, client)
  --this function should be used to turn normal socket into ssl stream
  --for the possibility of being subsituted with alternative library(like luaclr which is C# only)
  --sock is a connected socket
  --close a flag indicate if the underlying socket should be closed if the ssl stream is closed
  --auth  is a callback function to determine if security policy is allowed
  --keycert is a callback function to retrieve the x509 key use(if there is multiple)
  --client indicate if this stream is for client or server(as the handshaking is different)
  local x = lxyssl.ssl(client)
  x:keycert(keycert and kercert()) --setup server cert, would use embedded testing one none is given
  x:connect(sock:getfd())
  if copas then
    x:settimeout(0) -- copas needs non-blocking
    return copas.wrap(x) -- return a standard copas wrapped object
  else
    x:settimeout() -- default to blocking mode
    return bufferio.wrap(x) -- return a standard bufferio object
  end
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
