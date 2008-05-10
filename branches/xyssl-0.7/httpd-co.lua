require'socket'
require'lxyssl'
require'bufferio'
require 'copas' 
require'lasync'
format = string.format
local libhandle = lasync.handle()

SESSION_LIVE = 2400
SESSION_ROUNDS = 1000
MAX_SESSIONS = 10000
MAX_SSL = 100
--copas.WATCH_DOG_TIMEOUT = 600
--copas.SELECT = lxyssl.ev_select

local function proto_index(o, k)  
    --local v = o.__proto[k]
    local v = rawget(o, '__proto')[k]
    if type(v) == "function" then return function(x,...) return v(o.__proto,...) end 
    else return v end
end

local function prototype(o)
    return setmetatable({__proto=o}, {__index = proto_index })
end

local function header(l)
    local k,v = l:match("^%s*([^:]*):(.*)$")
    return k:match("^%s*(.-)%s*$"), v:match("^%s*(.-)%s*$")
end

local function keep_alive(proto, c)
    if proto:find('1.0') and c == 'keep-alive' then
        return "Connection: Keep-Alive\r\n"
    end
end

local function H501(obj,verb, h,uri,proto,read,write)
    local data
    local alive = keep_alive(proto, h['connection'])
    write(format("%s 501 No Implemented\r\n", proto))
    if alive then write(alive) end
    write("Content-Type: plain/text\r\n")
    local r  = format("%s %s\r\n", verb, uri)
    write(format("Content-Length: %i\r\n", #r))
    write("\r\n")
    write(r)
end

local function H404(obj,verb, h,uri,proto,read,write)
    local data
    local alive = keep_alive(proto, h['connection'])
    write(format("%s 404 Not Found\r\n", proto))
    if alive then write(alive) end
    write("Content-Type: plain/text\r\n")
    local r  = format("%s %s\r\n", verb, uri)
    write(format("Content-Length: %i\r\n", #r))
    write("\r\n")
    write(r)
end

local dispatch={
    ['GET'] = function(obj,verb, h,uri,proto,read,write)
        local data= format("%s %s %s\r\n", verb, uri, ("a"):rep(3))
        local alive = keep_alive(proto, h['connection'])
        write(format("%s 200 OK\r\n",proto))
        local too_old = os.difftime(os.time(), obj.birthday) >= SESSION_LIVE or obj.freq >= SESSION_ROUNDS 
        if alive and not too_old then write(alive) end
        if too_old and not proto:find('1.0') then write("Connection: close\r\n") end
        write("Content-Type: plain/text\r\n")
        write(format("Content-Length: %i\r\n", #data))
        write("\r\n")
        write(data)
    end,
    ['PUT'] = function(obj,verb, h,uri,proto,read,write)
        local data
        local alive = keep_alive(proto, h['connection'])
        if h['content-length'] then
           data=b:receive(h['content-length'])
        elseif h['transfer-encoding'] and h['transfer-encoding']:find('chunked') then
            local cnt
            local c={}
            repeat
                cnt,err,chunk = read()
                if cnt and #cnt > 0 then
                   c[#c+1]=read(cnt) 
                end
                read()
            until cnt == 0
            data = table.concat(c,"")
        else
            
        end
        write(format("%s 200 OK\r\n", proto))
        local too_old = os.difftime(os.time(), obj.birthday) > SESSION_LIVE or obj.freq < SESSION_ROUNDS 
        if alive or not proto:find('1.0') then
            if too_old then write("Connection: close\r\n")
            elseif alive then write(alive) end
        end
        write("Content-Type: plain/text\r\n")
        local r  = format("%s %s size %i\r\n", verb, uri, #data)
        write(format("Content-Length: %i\r\n", #r))
        write("\r\n")
        write(r)
    end,
}

local function handler(skt,is_ssl)
    skt:setoption('tcp-nodelay', true)
    local ip,port = skt:getsockname()

    local x = lxyssl.ssl(1) --1 is ssl server nil or 0 is client
    --local b = bufferio.wrap(port == 4433 and x or skt, true, port ~= 4433)
    local b = is_ssl and bufferio.wrap(x, true) or prototype(skt)
    local ev = libhandle:event(skt:getfd(), b):open()

    if not port then return end
    x:keycert() --setup server cert, would use embedded testing one none is given
    x:connect(skt:getfd())
    
    --b:settimeout(-1)
    local function read(...) return copas.receive(b,...) end 
    local function write(...) return copas.send( b,...) end 
    local obj = b
    
    --obj.event = lxyssl.event(obj:getfd(), obj)
    obj.birthday = os.time()
    obj.freq = 1
    --obj.probe = function(skt) return lxyssl.probe(skt:getfd()) end
    --local client = (port == 4433) and copas.wrap(b) or copas.wrap(skt)
    --local client = copas.wrap(skt)
    local action,err,chunk = read()
    while action and #action > 0 do
        local h = {}
        local data
        local verb, resource, proto = action:match("^%s*([^%s]*)%s+([^%s]*)%s+(.*)$")
        if not verb then break end
        repeat
            local l,err,chunk = read()
            if l and #l > 0 then
                local k,v = header(l)
                h[k:lower()]=v:lower()
            end
        until not l or #l==0
        local f = dispatch[verb:upper()]
        if not f then f = dispatch['H501'] end
        if f then 
            f(obj,verb, h, resource, proto, read, write) 
        else
            H501(obj,verb, h, resource, proto, read, write) 
        end
        if (not proto:find("1.0") or h['connection'] == 'keep-alive') 
            and os.difftime(os.time(), obj.birthday) < SESSION_LIVE 
            and obj.freq < SESSION_ROUNDS then 
            action, err, chunk = read()
            obj.freq = obj.freq + 1
        else action = nil end
    end
    --obj:close() 
    x:close()
    if ev then ev:close() end
end

local e
local ssl_connections = 0
local connections = 0
local function server(p,ssl)
    local function http_handler(skt)
        if ssl_connections > MAX_SESSIONS then return end
        connections = connections + 1 
        local x =  {handler(skt)}
        connections = connections - 1 
        return unpack(x)
    end
    local function https_handler(skt)
        if ssl_connections > MAX_SSL then return end
        ssl_connections = ssl_connections + 1
        print("new ssl connection", ssl_connections)
        local x =  {handler(skt,1)}
        ssl_connections = ssl_connections - 1
        return unpack(x)
    end

    local tcp = socket.bind("*",tonumber(p))
    --e = libhandle:event(tcp:getfd(), tcp):open()
    if ssl then copas.addserver(tcp, https_handler)
    else copas.addserver(tcp, http_handler) end
end

server(4433,1)
server(8080)
--server(8080)
--copas.event_loop()
while true do
    copas.step(0.1)
    --print(connections)
    --local x = tcp:accept()
    --if x then proxy_handler(x) end
end
--[[
t = socket.bind('localhost',4433)
while true do
s = t:accept()
handler(s)
end]]