--simple echo server
require'socket'
require'lxyssl'
t=socket.bind('localhost',4433)
x=lxyssl.new(1) --1 is ssl server nil or 0 is client
x:keycert() --setup server cert, would use embedded testing one none is given

r=0
out=0
s=t:accept()
x:connect(s:getfd())
chunk = 50 --chunk size to read
repeat 
d,err,p=x:receive(chunk)
if d then 
    r = r + #d
    l = 0
    repeat
        i,ret,l = x:send(d, l+1) 
        sent = i or l
    until sent >= #d or ret == "closed"
    out = out + sent

end
until not d and err ~= "timeout"
print("received", r, out)
print("verification", x:verify(), "\nremote cert:\n", x:peer(), "\nmyself cert:\n", x:name())
