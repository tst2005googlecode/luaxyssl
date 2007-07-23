require'xyssl'
require'socket'
t=socket.tcp()
x=xyssl.new()
x:keycert()
x:authmode(2,"hello")
x:connect(t:getfd())
t:connect('localhost',4433)
print(x:handshake())
print(x:verify(),x:peer(), x:name())
x:send('get')
d,err=x:receive(1000)
while err=="timeout" do
    d,err=x:receive(1000)
end
print(d)
