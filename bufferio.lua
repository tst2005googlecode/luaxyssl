--[[
--
a buffer io module to simulate luasocket's io function
on top of raw non-buffered raw io objects(pipe/ssl etc.)

Copyright 2007 Gary Ng<linux@garyng.com>
This code can be distributed under the LGPL license

--]]
local meta={};meta.__index = meta
local type=type
local getmetatable=getmetatable
local setmetatable=setmetatable
local pairs=pairs
local print=print
local tjoin=table.concat
local string=string

module'bufferio'

local CHUNK_SIZE = 8192

function wrap(p, buffered_write)
    local o = {p=p, buffered_write=buffered_write}
    for k,v in pairs(getmetatable(p).__index) do
        if type(v) == "function" then
            o[k] = function(self,...)
                local f = v
                return v(self.p,...)
            end
        end
    end
    o.receive = receive
    o.send = send
    o.dirty = dirty
    
    return o
end

function dirty(self)
    return (self._last and #self._last > 0) or self.p:dirty()
end

function receive(self, pattern, part)
    pattern = pattern or "*l"
    part = (part or "") .. (self._last or "") --all partial
    self._last = ""
    local size = #part
    if type(pattern) == "number" then
        local data, err, chunk
        if pattern > size then
            data,err,chunk = self.p:read(pattern - size)
            data = part .. (data or chunk or "")
            size = #data
        else
            data = part:sub(1, pattern) 
            self._last = part:sub(pattern + 1)
            size = pattern
        end
        if size < pattern then 
            return nil, err, data
        else return data end
    elseif pattern == "*a" or pattern == "*all" then
        local t={part}
        local data=""
        repeat 
            t[#t+1] = data
            local data,err,chunk = self.p:read(CHUNK_SIZE)
        until not data or #data == 0
        return tjoin(t,"")
    elseif pattern == "*l" then
        self._last = part
        local nl,data,err,chunk
        nl = self._last:find("\n")
        while not nl do
            data, err, chunk = self.p:read(64)
            self._last = self._last .. (data or chunk or "")
            if not data then break end
            nl = self._last:find("\n")
        end
        if nl then
            data = self._last:sub(1, nl - 1)
            self._last = self._last:sub(nl + 1)
            if data:sub(-1) == '\r' then return data:sub(1,-2)
            else return data end
        else
            data = self._last
            self._last = ""
            if err=="timeout" then return nil,err
            else return nil, err or "closed", data end
        end
    end
end

function send(self, data, i, j)
    if self.buffered_write then
       return self.p:write(data,i,j) 
    end
   
    i = i or 1
    j = j or #data

    if i > 1 then data = data:sub(i,j) end
    if #data == 0 then return i - 1 end
    
    local written,msg,e = self.p:write(data)

    if written then
        return i + written - 1
    else
        return nil, msg, i + e - 1
    end
end
