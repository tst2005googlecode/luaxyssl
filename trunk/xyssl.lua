local lxyssl = require 'lxyssl'
local socket = require 'socket'
local bufferio = require 'bufferio'
local url = require("socket.url")
local http = require("socket.http")
local ltn12 = require("ltn12")
local setmetatable = setmetatable
local rawget = rawget
local type=type
local print=print
local ipairs=ipairs
local pairs=pairs
local tconcat=table.concat
local tostring=tostring
module 'xyssl'

local function proto_index(o, k)  
    --local v = o.__proto[k]
    local v = rawget(o, '__proto')[k]
    if type(v) == "function" then return function(x,...) return v(o.__proto,...) end 
    else return v end
end

local function prototype(o)
    return setmetatable({__proto=o}, {__index = proto_index })
end

local function connect(self,...)
  local r, e = self.__proto:connect(...)
  if r then
    if self.ssl then
      local x = lxyssl.ssl(0)  -- SSL client object
      local b = bufferio.wrap(x)
      x:connect(self:getfd())
      x:settimeout()
      setmetatable(self, b)
    else
      self.__proto:settimeout()
    end
    return 1
  end
  return r, e
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
    local code, headers, status = socket.skip(1, socket.http.request(reqt))
    return tconcat(t), code, headers, status
  else
    local nreqt = {}
    for k,v in pairs(reqt) do nreqt[k]= v end
    nreqt.create = reqt.create or tcp
    return socket.http.request(nreqt) 
  end
end

function tcp(scheme)
  local o = prototype(socket.tcp())
  o.connect = connect
  o.ssl = scheme == "https"
  return o
end
