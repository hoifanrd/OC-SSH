local component = require("component")
local sha256 = require("cryptolib.sha256")

local HMAC_KEY_LEN = 32
local HMAC_LEN = 32

HMAC_SHA2 = {}
HMAC_SHA2.__index = HMAC_SHA2

function HMAC_SHA2.new()
  local obj = {}
  obj.key = nil
  setmetatable(obj, HMAC_SHA2)
  return obj
end


function HMAC_SHA2:set_key(key)
  self.key = key
end


function HMAC_SHA2:create_hmac(data)
  local rtn = nil
  while rtn == nil do
    rtn = sha256.hmac(data, self.key)
  end
  return rtn
end


function HMAC_SHA2.get_key_len()
  return HMAC_KEY_LEN
end


function HMAC_SHA2.get_hmac_len()
  return HMAC_LEN
end

return HMAC_SHA2