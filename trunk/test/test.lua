require'bufferio'
require'socket'
require'lxyssl'
require'security'
require'ssl'
string.hex = function(x)
    local t={}
    for c in x:gmatch('(.)') do t[#t+1]=string.format("%02x", c:byte()) end
    return table.concat(t,"")
end

local function proto_index(o, k)  
    --local v = o.__proto[k]
    local v = rawget(o, '__proto')[k]
    if type(v) == "function" then return function(x,...) return v(o.__proto,...) end 
    else return v end
end

local function prototype(o)
    return setmetatable({__proto=o}, {__index = proto_index })
end

assert(security.hash.engine('md5'):digest(''):hex() == "d41d8cd98f00b204e9800998ecf8427e")
assert(security.hash.engine('sha'):digest(''):hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
assert(security.hash.engine('sha1'):digest(''):hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
assert(security.hash.engine('sha2'):digest(''):hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
assert(security.hash.engine('sha256'):digest(''):hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
assert(security.hmac.engine('md5','test'):digest('test'):hex()=="cd4b0dcbe0f4538b979fb73664f51abe")
assert(security.hmac.engine('sha','test'):digest('test'):hex()=="0c94515c15e5095b8a87a50ba0df3bf38ed05fe6")
assert(security.hmac.engine('sha1','test'):digest('test'):hex()=="0c94515c15e5095b8a87a50ba0df3bf38ed05fe6")
assert(security.hmac.engine('sha2','Jefe'):digest('what do ya want for nothing?'):hex()=="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
assert(security.hmac.engine('sha256','Jefe'):digest('what do ya want for nothing?'):hex()=="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
data=('a'):rep(8192)
iv=lxyssl.hash('md5'):digest(key)
k = security.hash.engine('md5'):digest('abcd')
a = security.crypto.engine('aes',k)
assert(a:decrypt(a:encrypt(data)) == data)
a = security.crypto.engine('aes_cbc', k, k)
assert(a:decrypt((a:encrypt(data))) == data)
a = security.crypto.engine('aes_cfb', k, k)
assert(a:decrypt((a:encrypt(data))) == data)
a = security.crypto.engine('rc4', k)
b = security.crypto.engine('rc4', k)
assert(b:decrypt((a:encrypt(data))) == data)
assert(security.rand(256) ~= security.rand(256))

a=security.rsa.sign('abc')
assert(security.rsa.verify('abc', a))

a=security.rsa.encrypt('abc')
assert(security.rsa.decrypt(a)=='abc')

gx,x,p,g=security.dh.params(256)
gy,y = security.dh.params(256, p, g)
gxy = security.dh.secret(gx, y, p, g)
gyx = security.dh.secret(gy, x, p, g)
assert(gxy==gyx)

host='www.google.com'
host='www.yahoo.com'
host='www.microsoft.com'
--host='www.dreamhost.com'
port=443
--x:connect(t:getfd())
--b:settimeout(-1)
msg = string.format('GET / HTTP/1.1\r\nHost: %s\r\n\r\n', host)
for i =1,10 do 
--x=lxyssl.ssl()
--b=bufferio.wrap(x)
t=socket.tcp()
t:connect(host,port)
--b:connect(t:getfd())
b = ssl.stream(t)
if id then 
    lid = id
    b:sessinfo(id,master,cipher,start) 
end
c=0
--print(msg)
repeat
    o,err,c = b:send(msg,c+1)
    --o,err,c = x:send('GET / HTTP/1.1\r\nhost: www.yahoo.com\r\n\r\n')
until o==#msg or err ~= "timeout"

--print(i, b:peer(), b:name(), b:cipher())

repeat
    d,err,_ = b:receive()
    --d,err,i = x:receive(1000)
    if not err then 
        print(d)
        if d=='' then 
            break 
        end
    else
    end
until err == "closed" or err=="nossl"
if err ~= "nossl" and err ~= "nossl" then b:receive('*a') end
id,master,cipher,start = b:sessinfo()
print(i, lid and lid:hex(), id:hex(),id==lid)
if id==lid then print("session reuse", id:hex(), master:hex()) end
--print("cipher used:", b:cipher(), "peer:", b:peer(), "name:", b:name())
--b:reset()
--b:close()
--t:close()
end
md5=lxyssl.hash('md5')
md5:update('a')
md5:update('b')
md5:update('cde')
assert(lxyssl.hash('md5'):digest('abcde') == md5:digest())
assert(lxyssl.hash('md5'):digest('abcde') == md5:reset():digest('abcde'))
sha1=lxyssl.hash('sha1')
sha1:update('a')
sha1:update('b')
sha1:update('cde')
assert(lxyssl.hash('sha1'):digest('abcde') == sha1:digest())
assert(lxyssl.hash('sha1'):digest('abcde') == sha1:reset():digest('abcde'))
assert(lxyssl.hash('sha1'):digest() == lxyssl.hash('sha1'):digest(''))
assert(lxyssl.hash('md5'):digest() == lxyssl.hash('md5'):digest(''))
assert(lxyssl.hash('md5'):digest(''):hex() == "d41d8cd98f00b204e9800998ecf8427e")
assert(lxyssl.hash('hmac-md5','test'):digest('test'):hex()=="cd4b0dcbe0f4538b979fb73664f51abe")
assert(lxyssl.hash('hmac-sha1','test'):digest('test'):hex()=="0c94515c15e5095b8a87a50ba0df3bf38ed05fe6")

key='abcdabcdabcdabcd'
data=('a'):rep(8192)
iv=lxyssl.hash('md5'):digest(key)
assert(lxyssl.aes(key):decrypt(lxyssl.aes(key):encrypt(data)) == data)
assert(lxyssl.aes(key):cbc_decrypt(lxyssl.aes(key):cbc_encrypt(data,iv),iv) == data)
assert(lxyssl.aes(key):cfb_decrypt(lxyssl.aes(key):cfb_encrypt(data .. "a",iv),iv) == data .."a")
assert(lxyssl.rc4(key):crypt(lxyssl.rc4(key):crypt(data)) == data)
assert(#lxyssl.rand(2000) == 2000)
assert(lxyssl.rand(2000) ~= lxyssl.rand(2000))
t = {}
e = lxyssl.aes(key)
iv=lxyssl.hash('md5'):digest(key)
for i=1,10 do
    d,iv = e:cbc_encrypt(data,iv)
    t[i]=d
end

e = lxyssl.aes(key)
iv=lxyssl.hash('md5'):digest(key)
for i=1,10 do
    d,iv = e:cbc_decrypt(t[i],iv)
    t[i]=d
end

assert(table.concat(t,"")==data:rep(10))

data=('abc'):rep(95)
t = {}
e = lxyssl.aes(key)
iv=lxyssl.hash('md5'):digest(key)
start=0
for i=1,10 do
    d,iv,start = e:cfb_encrypt(data,iv, start)
    t[i]=d
end

start = 0
e = lxyssl.aes(key)
iv=lxyssl.hash('md5'):digest(key)
for i=1,10 do
    d,iv,start = e:cfb_decrypt(t[i],iv,start)
    t[i]=d
end

assert(table.concat(t,"")==data:rep(10))

a=lxyssl.rsasign('abc')
assert(lxyssl.rsaverify('abc', a))

a=lxyssl.rsaencrypt('abc')
assert(lxyssl.rsadecrypt(a)=='abc')

P256="BC128EC94B1A9AEA42FBD79EC9434F5DF1B07852F2773769F9A13F209CAFBC9B"
G = "04"

P512="9A1EC9FBD2F2AC04FEE7F52687C9E57D7362446CBDB8F875B1681189FB4B38EF586BEC35ABAF718378467424143C5DD0937387FB4590D723D168FACDBC62E65B"

G = "04"

gx,x,p,g=lxyssl.dhmparams(256,P512,G)
gy,y = lxyssl.dhmparams(256,p,g)
gz,z = lxyssl.dhmparams(256,p,g)
assert(x)
assert(g)
assert(p)
assert(gx)
assert(gy)
assert(gz)
assert(gx ~= gy)
assert(gy ~= gz)
assert(gx ~= gz)
xy = lxyssl.dhmsecret(gy,x, p,g)
yx = lxyssl.dhmsecret(gx,y, p,g)
zy = lxyssl.dhmsecret(gy,z, p,g)
yz = lxyssl.dhmsecret(gz,y, p,g)
zx = lxyssl.dhmsecret(gx,z, p,g)
xz = lxyssl.dhmsecret(gz,x, p,g)
assert(xy==yx and zy == yz and xz==zx)
print(#xy,#gx,#p,#g)

print("test done")
