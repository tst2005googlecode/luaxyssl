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
local time=os.time
local tjoin=table.concat
local string=string

module'bufferio'

local CHUNK_SIZE = 8192


local function dirty(self)
    --local x,err,c = self:receive(0)
    return (self._last and #self._last > 0) or self.p:dirty() or self.closed
end

local function receive(self, pattern, part)
    local underlying_read = self.p.read or self.p.receive

    if self.buffered_read then
       --local x,msg,chunk,q = self.p:receive(pattern,part) 
       local x,msg,chunk,q = underlying_read(self.p, pattern, part)
       if msg and msg ~= "timeout" then self.closed = true end 
       return x,msg,chunk,q
    end
    pattern = pattern or "*l"
    part = (part or "") .. (self._last or "") --all partial
    self._last = ""
    local size = #part
    if type(pattern) == "number" then
        local data, err, chunk,q
        if pattern == 0 or pattern > size then
            data,err,chunk,q = underlying_read(self.p, pattern == 0 and 256 or pattern - size)
            data = part .. (data or chunk or "")
            size = #data
            if pattern == 0 then self._last = data end
        else
            data = part:sub(1, pattern) 
            self._last = part:sub(pattern + 1)
            size = pattern
        end
        if err and err ~= "timeout" then self.closed = true end
        if size < pattern then 
            if not err then
              return receive(self, pattern, data)
            else
              return nil, err , data, q
            end
        elseif pattern == 0 and err then
            return nil, err, "", q
        else return data end
    elseif pattern == "*a" or pattern == "*all" then
        local t={part}
        local data=""
        local data,err,chunk,q
        repeat 
            t[#t+1] = data
            data,err,chunk,q = underlying_read(self.p, CHUNK_SIZE)
            if err and err ~= "timeout" then self.closed = true end
        until not data or #data == 0
        return tjoin(t,""), err,"",q
    elseif pattern == "*l" then
        self._last = part
        local nl,data,err,chunk,q
        nl = self._last:find("\n")
        while not nl do
            data, err, chunk,q = underlying_read(self.p, 64)
            self._last = self._last .. (data or chunk or "")
            nl = self._last:find("\n")
            if not data then break end
        end
        if nl then
            data = self._last:sub(1, nl - 1)
            self._last = self._last:sub(nl + 1)
            if data:sub(-1) == '\r' then return data:sub(1,-2)
            else return data end
        else
            data = self._last
            self._last = ""
            if err and err ~= "timeout" then self.closed = true end
            if err=="timeout" then return nil, err, data or "",q
            else return nil, err or "closed", data,q end
        end
    end
end

local function send(self, data, i, j)
    local underlying_write = self.p.write or self.p.send
    if #data == 0 then
        local x,err,c,q = receive(self, 0)
        if err and err ~= "timeout" then 
            self.closed = true
            return nil,err,0,q 
        end
    end

    if self.buffered_write then
       --local x,err,c, q =  self.p:send(data,i,j) 
       local x,err,c, q =  underlying_write(self.p, data, i, j)
       if err and err ~= "timeout" then self.closed = true end
       return x,err,c,q
    end
   
    i = i or 1
    j = j or #data

    if i > 1 then data = data:sub(i,j) end
    if #data == 0 then return i - 1 end
    
    --local written,msg,e,q = self.p:send(data)
    local written,msg,e,q = underlying_write(self.p, data)

    if written then
        return i + written - 1
    else
        if msg and msg ~= "timeout" then self.closed = true end 
        if type(e) ~= "number" then e = 0; q = nil end
        return nil, msg, i + e - 1,q
    end
end

function wrap(p, buffered_write,buffered_read)
    if buffered_write == nil then buffered_write = p.buffered_write end
    local o = {p=p, buffered_write=buffered_write,buffered_read=buffered_read}
    for k,v in pairs(getmetatable(p).__index) do
        if type(v) == "function" then
            o[k] = function(self,...)
                local f = v
                return v(self.p,...)
            end
        end
    end
    o.receive = receive
    o.read = receive
    o.send = send
    o.write = send
    o.dirty = dirty
    o.__index = o
    
    return o
end
