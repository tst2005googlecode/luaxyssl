require'bufferio'
require'socket'
require'lxyssl'

t=socket.tcp()
x=lxyssl.new()
b=bufferio.wrap(x,true)
--x:connect(t:getfd())
b:connect(t:getfd())
t:connect('www.microsoft.com',443)
--b:settimeout(-1)
msg = 'GET / HTTP/1.1\r\nHost: www.microsoft.com\r\n\r\n'
for i =1,100 do
c=0
print(msg)
repeat
    o,err,c = b:send(msg,c)
    --o,err,c = x:send('GET / HTTP/1.1\r\nhost: www.yahoo.com\r\n\r\n')
until o==#msg or err ~= "timeout"

repeat
    d,err,i = b:receive()
    --d,err,i = x:receive(1000)
    if not err then 
        print(d)
        if d=='' then 
            break 
        end
    end
until err == "closed" or err=="nossl"
end
