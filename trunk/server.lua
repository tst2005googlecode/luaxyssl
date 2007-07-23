require'socket'
require'xyssl'
t=socket.bind('localhost',4433)
x=xyssl.new(1)
x:keycert()
x:authmode(1)

s=t:accept()
x:connect(s:getfd())
x:handshake()
print(x:verify(),x:peer(), x:name())
d,err=x:receive(100)
while d or err=="timeout" do
    d,err = x:receive(100)
    if d then 
        print("from client:", d)
        x:send(d) 
    end
end
