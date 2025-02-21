package.loaded.utils = nil
require("utils")

local component = require("component")

local KEY_LENGTH = 16
local IV_LENGTH = 16

AES128_CTR = {}
AES128_CTR.__index = AES128_CTR

-- https://datatracker.ietf.org/doc/html/rfc4344#section-4
function AES128_CTR.new()
  local obj = {}
  obj.key = nil
  obj.iv = nil
  setmetatable(obj, AES128_CTR)
  return obj
end

-- Must be multiple of 16
function AES128_CTR:encrypt(msg)

  local ct = ""
  while #msg > 0 do
    local chunk = msg:sub(1, KEY_LENGTH)
    msg = msg:sub(KEY_LENGTH + 1)
    ct = ct .. self:encrypt_chunk(chunk)
  end
  return ct

end

function AES128_CTR:decrypt(msg)
  return self:encrypt(msg)
end


function AES128_CTR:set_key_iv(key, iv)
  self.key = key
  self.iv = iv
end

function AES128_CTR.get_key_len()
  return KEY_LENGTH
end

function AES128_CTR.get_iv_len()
  return IV_LENGTH
end

function AES128_CTR.get_chunk_len()
  return KEY_LENGTH
end


-- Priv functions

function AES128_CTR:encrypt_chunk(chunk)

  assert( #chunk == KEY_LENGTH )

  local PKCS7_PAD = "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
  local stream = component.data.encrypt("", self.key, xor(self.iv, PKCS7_PAD))
  local ct = xor(stream, chunk)
  
  self:incr_ctr()

  return ct

end


function AES128_CTR:incr_ctr()
  self.iv = incr_bitstr(self.iv)
end



return AES128_CTR