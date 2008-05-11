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

local function proto_index(o, k)  
    --local v = o.__proto[k]
    local v = rawget(o, '__proto')[k]
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
  if (self.__ssl) then 
    if copas and copas.release then copas.release(self.__ssl) end
    self.__ssl:close() 
  end
  self.__ssl = nil
  if (self.__proto) then 
    if copas and copas.release then copas.release(self.__proto) end
    self.__proto:close() 
  end
  self.__proto = nil
end

local function connect(self,...)
  local r, e = copas and copas.connect(self.__proto, ...) or self.__proto:connect(...)
  if r then
    self.__proto:setoption('tcp-nodelay',true)
    if self.ssl then
      local x = lxyssl.ssl(0)  -- SSL client object
      if debug then x:debug(debug or 0) end
      x:connect(self:getfd())
      if copas and async_handshake == false then 
        x:settimeout() 
        x:handshake()
      end
      local b = bufferio.wrap(x)
      if copas then x:settimeout(async_timeout) else x:settimeout() end
      setmetatable(self,b)
      self.__ssl = b
      self.close = close
    else
      local b = bufferio.wrap(self.__proto)
      if copas then self.__proto:settimeout(async_timeout) else self.__proto:settimeout() end
      --self.__proto:settimeout(self.timeout)
      --setmetatable(self,b)
    end
    if copas then
      self.receive = function(self, ...) 
        local skt = self.__ssl or self.__proto
        if skt then return copas.receive(skt,...)
        else return nil, "closed", ""  end
      end
      self.send = function(self, ...) 
        local skt = self.__ssl or self.__proto
        if skt then return copas.send(skt,...)
        else return nil, "closed", ""  end
      end
    end
    return 1
  end
  return r, e
end

local function settimeout(self, t)
 self.timeout = t
 return (self.__ssl or self.__proto):settimeout(t)
end

local function gettimeout(self, t)
 self.timeout = t
 return 1
end

function async(dispatcher)
  copas = dispatcher
  http.copas = dispatcher
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
  x:settimeout() -- default to blocking mode
  return bufferio.wrap(x) -- return a standard bufferio object
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
  if not copas and scheme ~= "https" then return socket.tcp() end
  local o = prototype(socket.tcp())
  o.connect = connect
  o.settimeout = settimeout
  o.gettimeout = gettimeout
  o.close = close
  o.ssl = scheme == "https"
  return o
end
