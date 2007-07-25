require'lxyssl'
require'socket'
t=socket.tcp()
x=lxyssl.ssl()
x:keycert()
x:authmode(2,'localhost')
x:connect(t:getfd())
t:connect('localhost',4433)
--print(string.format("%X",x:handshake()))

test = ('a'):rep(200000)
b = {}
sent = 0
r = 0
chunk=100
while r < #test do
if sent < #test then
repeat 
    d,err,i = x:send(test,sent + 1)
    sent = d or i
until not d or sent >= #test
end
repeat 
    d,err,j = x:receive(chunk)
    if d then 
        r = r + #d 
        b[#b+1]=d
    end
until not d
end
print(sent,r)
assert(table.concat(b,"") == test)
print("verification", x:verify(), "\nremote cert:\n", x:peer(), "\nmyself cert:\n", x:name())
