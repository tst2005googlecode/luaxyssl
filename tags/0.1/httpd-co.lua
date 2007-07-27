require'socket'
require'lxyssl'
require'bufferio'
require 'copas' 
format = string.format

local function header(l)
    local k,v = l:match("^%s*([^:]*):(.*)$")
    return k:match("^%s*(.-)%s*$"), v:match("^%s*(.-)%s*$")
end

local function keep_alive(proto, c)
    if proto:find('1.0') and c == 'keep-alive' then
        return "Connection: Keep-Alive\r\n"
    end
end

local function H501(verb, h,uri,proto,read,write)
    local data
    write(format("%s 501 No Implemented\r\n", proto))
    if alive then write(alive) end
    write("Content-Type: plain/text\r\n")
    local r  = format("%s %s\r\n", verb, uri)
    write(format("Content-Length: %i\r\n", #r))
    write("\r\n")
    write(r)
end

local dispatch={
    ['GET'] = function(verb, h,uri,proto,read,write)
        local data= format("%s %s %s\r\n", verb, uri, ("a"):rep(3))
        local alive = keep_alive(proto, h['connection'])
        write(format("%s 200 OK\r\n",proto))
        if alive then write(alive) end
        write("Content-Type: plain/text\r\n")
        write(format("Content-Length: %i\r\n", #data))
        write("\r\n")
        write(data)
    end,
    ['PUT'] = function(verb, h,uri,proto,read,write)
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
        if alive then write(alive) end
        write("Content-Type: plain/text\r\n")
        local r  = format("%s %s size %i\r\n", verb, uri, #data)
        write(format("Content-Length: %i\r\n", #r))
        write("\r\n")
        write(r)
    end,
}

local function handler(skt)
    local x = lxyssl.ssl(1) --1 is ssl server nil or 0 is client
    local b = bufferio.wrap(x,true)

    b:keycert() --setup server cert, would use embedded testing one none is given
    b:connect(skt:getfd())
    
    --b:settimeout(-1)
   
    local client = copas.wrap(b)
    local action,err,chunk = client:receive()
    while action do
        local h = {}
        local data
        local verb, resource, proto = action:match("^%s*([^%s]*)%s+([^%s]*)%s+(.*)$")
        repeat
            l,err,chunk = client:receive()
            --print(l,#l,err,chunk)
            if l and #l > 0 then
                local k,v = header(l)
                h[k:lower()]=v:lower()
            end
        until not l or #l==0
        local f = dispatch[verb:upper()]
        if not f then f = dispatch['H501'] end
        if f then 
            f(verb, h, resource, proto, function(...) return b:receive(...) end, function(...) return b:send(...) end) 
        else
            H501(verb, h, resource, proto, function(...) return b:receive(...) end, function(...) return b:send(...) end) 
        end
        if not proto:find("1.0") or h['connection'] == 'keep-alive' then 
            action, err, chunk = client:receive()
        else action = nil end
    end
    b:close()
end

local function server(p)
    local tcp = socket.bind("*",tonumber(p))
    copas.addserver(tcp, handler)
    while true do
        copas.step()
        --local x = tcp:accept()
        --if x then proxy_handler(x) end
    end
end

server(4433)
--[[
t = socket.bind('localhost',4433)
while true do
s = t:accept()
handler(s)
end]]
