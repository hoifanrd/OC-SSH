local component = require("component")
local ber = require("ber")

-- Output bytes of SHA256
local HASH_OUTPUT_LEN = 32
local HASH_FUNC = component.data.sha256

ECDH_Proto = {}
ECDH_Proto.__index = ECDH_Proto

function ECDH_Proto.new()
  local obj = {}
  obj.pubkey_client, obj.privkey_client = component.data.generateKeyPair(256)
  obj.pubkey_server = nil
  obj.shared_key = nil
  obj.exchange_hash = nil
  setmetatable(obj, ECDH_Proto)
  return obj
end

function ECDH_Proto:get_pubkey_client_bytes()
  local seriX509 = self.pubkey_client.serialize()
  local pubBitStr = ber.decode(seriX509).children[2].data

  -- 1st byte of bit string identify num of bits to get rid from the end
  -- must be 0 in this case
  assert( string.byte(pubBitStr, 1) == 0 )
  pubBitStr = pubBitStr:sub(2)
  
  return pubBitStr
end

function ECDH_Proto:get_pubkey_server_bytes()
  local seriX509 = self.pubkey_server.serialize()
  local pubBitStr = ber.decode(seriX509).children[2].data

  -- 1st byte of bit string identify num of bits to get rid from the end
  -- must be 0 in this case
  assert( string.byte(pubBitStr, 1) == 0 )
  pubBitStr = pubBitStr:sub(2)
  
  return pubBitStr
end


function ECDH_Proto:perform_exchange(pubkey_server_bytes)
  local seriX509 = self.pubkey_client.serialize()
  local pubkeyBer = ber.decode(seriX509)

  local algoIdentifier = ber.encode({
    type = pubkeyBer.children[1].type,
    data = pubkeyBer.children[1].data
  })

  local subjectPublicKey = ber.encode({
    type = pubkeyBer.children[2].type,
    data = string.char(0) .. pubkey_server_bytes
  })

  local constructedX509 = ber.encode({
    type = pubkeyBer.type,
    data = algoIdentifier .. subjectPublicKey
  })

  self.pubkey_server = component.data.deserializeKey(constructedX509, "ec-public")

  if self.pubkey_server == nil then
    error("Invalid server public key for ecdh-sha2-nistp256!")
  end

  self.shared_key = component.data.ecdh(self.privkey_client, self.pubkey_server)

end


function ECDH_Proto:generate_exchange_hash(V_C, V_S, I_C, I_S, K_S)
  
  local Q_C = self:get_pubkey_client_bytes()
  local Q_S = self:get_pubkey_server_bytes()
  local K = self.shared_key

  local payload = ""
  payload = payload .. string.pack(">I4", #V_C) .. V_C
  payload = payload .. string.pack(">I4", #V_S) .. V_S
  payload = payload .. string.pack(">I4", #I_C) .. I_C
  payload = payload .. string.pack(">I4", #I_S) .. I_S
  payload = payload .. string.pack(">I4", #K_S) .. K_S
  payload = payload .. string.pack(">I4", #Q_C) .. Q_C
  payload = payload .. string.pack(">I4", #Q_S) .. Q_S
  payload = payload .. to_mpint(K)

  self.exchange_hash = HASH_FUNC(payload)

end

-- https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
function ECDH_Proto:get_initial_key(X, session_id, key_len)
  
  local K = to_mpint(self.shared_key)
  local H = self.exchange_hash

  local res = HASH_FUNC(K .. H .. X .. session_id)
  if key_len <= HASH_OUTPUT_LEN then
    return res:sub(1, key_len)
  end

  key_len = key_len - HASH_OUTPUT_LEN
  while key_len > 0 do
    local extra_part = HASH_FUNC(K .. H .. res)
    if key_len <= HASH_OUTPUT_LEN then
      return res .. extra_part:sub(1, key_len)
    end
    res = res .. extra_part
    key_len = key_len - HASH_OUTPUT_LEN
  end

end



return ECDH_Proto