require'lxyssl'

module('security',package.seeall)
rand = lxyssl.rand

module('security.hash', package.seeall)
function engine(engine)
  local algo = {md5 = 'md5', sha1 = 'sha1', sha2 = 'sha2', sha256 = 'sha256'}
  return lxyssl.hash(algo[engine])
end

module('security.hmac', package.seeall)
function engine(engine, key)
  local algo = {md5 = 'hmac-md5', sha1 = 'hmac-sha1', sha2 = 'hmac-sha2', sha256 = 'hmac-sha256'}
  return lxyssl.hash(algo[engine], key)
end

module('security.crypto', package.seeall)
local aes_object = {
  encrypt = function(self, x) return self.e:encrypt(x) end,
  decrypt = function(self, x) return self.e:decrypt(x) end,
  }; aes_object.__index = aes_object;

local aes_cfb_object = {
  encrypt = function(self, x, iv) return self.e:cfb_encrypt(x,iv or self.iv) end,
  decrypt = function(self, x, iv) return self.e:cfb_decrypt(x,iv or self.iv) end,
  }; aes_cfb_object.__index = aes_cfb_object;

local aes_cbc_object = {
  encrypt = function(self, x, iv) return self.e:cbc_encrypt(x,iv or self.iv) end,
  decrypt = function(self, x, iv) return self.e:cbc_decrypt(x,iv or self.iv) end,
  }; aes_cbc_object.__index = aes_cbc_object;

local rc4_object = {
  encrypt = function(self, x) return self.e:crypt(x) end,
  decrypt = function(self, x) return self.e:crypt(x) end,
  }; rc4_object.__index = rc4_object;

function engine(engine, key, iv)
  local algo = {
    aes = function(x) return setmetatable({e = lxyssl.aes(x)}, aes_object) end,
    aes_cfb = function(x) return setmetatable({e = lxyssl.aes(x)}, aes_cfb_object) end,
    aes_cbc = function(x) return setmetatable({e = lxyssl.aes(x)}, aes_cbc_object) end,
    rc4 = function(x) return setmetatable({e = lxyssl.rc4(x)}, rc4_object) end,
    }
  local o = algo[engine](key)
  o.iv = iv
  return o
end

module('security.rsa', package.seeall)

function sign(data, key, password_for_key)
  return lxyssl.rsasign(data, key, password_for_key)
end

function verify(data, sig, crt)
  return lxyssl.rsaverify(data, sig, crt)
end

function encrypt(data, crt)
  return lxyssl.rsaencrypt(data, crt)
end

function decrypt(data, key, password_for_key)
  return lxyssl.rsadecrypt(data, key, password_for_key)
end

module('security.x509', package.seeall)

function verify(crt, ca)
  return lxyssl.x509verify(ca, crt)
end

module('security.dh', package.seeall)

function params(bits, P, G)
  return lxyssl.dhmparams(bits, P, G)
end

function secret(GY, X, P, G)
  return lxyssl.dhmsecret(GY, X, P, G)
end


