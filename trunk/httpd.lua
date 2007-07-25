require'socket'
require'lxyssl'
require'bufferio'
format = string.format

local function header(l)
    local k,v = l:match("^%s*([^:]*):(.*)$")
    return k:match("^%s*(.-)%s*$"), v:match("^%s*(.-)%s*$")
end

local dispatch={
    ['GET'] = function(h,uri,read,write)
        local data= format("GET %s\r\n", uri)
        write("HTTP/1.1 200 OK\r\n")
        write("Content-Type: plain/text\r\n")
        write(format("Content-Length: %i\r\n", #data))
        write("\r\n")
        write(data)
    end,
    ['PUT'] = function(h,uri,read,write)
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
        else
        end
        write("HTTP/1.1 204 No Content\r\n'")
        write("Content-Type: plain/text\r\n'")
        write("\r\n'")
        write(format("PUT %s\r\n", uri))
    end,
}
local function handler(skt)
    local x = lxyssl.ssl(1) --1 is ssl server nil or 0 is client
    local b = bufferio.wrap(x)

    b:keycert() --setup server cert, would use embedded testing one none is given
    b:connect(skt:getfd())
    
    b:settimeout(-1)
   
    local action = b:receive()
    while action do
        local h = {}
        local l , err, chunk
        local data
        local verb, resource, proto = action:match("^%s*([^%s]*)%s+([^%s]*)%s+(.*)$")
        repeat
            l,err,chunk = b:receive()
            if l and #l > 0 then
                local k,v = header(l)
                h[k:lower()]=v:lower()
                print(k,v)
            end
        until err=="closed" or err=="nossl" or #l==0
        local f = dispatch[verb:upper()]
        if f then f(h, resource, function(...) b:receive(...) end, function(...) b:send(...) end) 
        else b:send("HTTP/1.1 501 Function not implemented\r\n\r\n") end
        if err=="closed" or err=="nossl" then break end
        action = b:receive()
    end
end

t = socket.bind('localhost',4433)
while true do
s = t:accept()
handler(s)
end
