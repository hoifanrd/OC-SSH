local component = require("component")
local ber = require("ber")

ECDSA_Proto = {}
ECDSA_Proto.__index = ECDSA_Proto

function ECDSA_Proto.new()
  local obj = {}
  obj.pubkey_server = nil
  setmetatable(obj, ECDSA_Proto)
  return obj
end



function ECDSA_Proto:set_pubkey_server(server_pub_host_key)
  
  -- https://datatracker.ietf.org/doc/html/rfc5656#section-3.1
  local proto_name_len = string.unpack(">I4", server_pub_host_key:sub(1, 4))
  local proto_name = server_pub_host_key:sub(5, 5 + proto_name_len - 1)
  server_pub_host_key = server_pub_host_key:sub(5 + proto_name_len)

  assert( proto_name == "ecdsa-sha2-nistp256")

  local identifier_len = string.unpack(">I4", server_pub_host_key:sub(1, 4))
  local identifier = server_pub_host_key:sub(5, 5 + identifier_len - 1)
  server_pub_host_key = server_pub_host_key:sub(5 + identifier_len)
  
  local pubkey_server_bytes_len = string.unpack(">I4", server_pub_host_key:sub(1, 4))
  local pubkey_server_bytes = server_pub_host_key:sub(5, 5 + pubkey_server_bytes_len - 1)

  
  -- Same as ecdh-sha2-nistp256
  local pubkey_server_template, _ = component.data.generateKeyPair(256)
  local seriX509 = pubkey_server_template.serialize()
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
    error("Invalid server host key for ecdsa-sha2-nistp256!", 0)
  end

end



function ECDSA_Proto:verify_sign(data, server_sign)

  -- https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
  local proto_name_len = string.unpack(">I4", server_sign:sub(1, 4))
  local proto_name = server_sign:sub(5, 5 + proto_name_len - 1)
  server_sign = server_sign:sub(5 + proto_name_len)

  assert( proto_name == "ecdsa-sha2-nistp256")

  local mpint_r_s_len = string.unpack(">I4", server_sign:sub(1, 4))
  local mpint_r_s = server_sign:sub(5, 5 + mpint_r_s_len - 1)

  local mpint_r_len = string.unpack(">I4", mpint_r_s:sub(1, 4))
  local mpint_r = mpint_r_s:sub(5, 5 + mpint_r_len - 1)
  mpint_r_s = mpint_r_s:sub(5 + mpint_r_len)

  local mpint_s_len = string.unpack(">I4", mpint_r_s:sub(1, 4))
  local mpint_s = mpint_r_s:sub(5, 5 + mpint_s_len - 1)

  -- The OC sign format is SEQ -> { INT, INT }
  local dsn_r = ber.encode({
    type = ber.Types.INTEGER,
    data = mpint_r
  })

  local dsn_s = ber.encode({
    type = ber.Types.INTEGER,
    data = mpint_s
  })

  local dsn_sign = ber.encode({
    type = ber.Types.SEQUENCE,
    data = dsn_r .. dsn_s
  })

  return component.data.ecdsa(data, self.pubkey_server, dsn_sign)

end

return ECDSA_Proto