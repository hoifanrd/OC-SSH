package.loaded.utils = nil
package.loaded.ssh_const = nil
require("utils")
require("ssh_const")

local component = require("component")
package.loaded.ecdh_sha2_nistp256 = nil
local ecdh_sha2_nistp256 = require("ecdh_sha2_nistp256")

package.loaded.ecdsa_sha2_nistp256 = nil
local ecdsa_sha2_nistp256 = require("ecdsa_sha2_nistp256")

package.loaded.aes128_ctr = nil
local aes128_ctr = require("aes128_ctr")

package.loaded.ssh_known_hosts = nil
local ssh_known_hosts = require("ssh_known_hosts")

package.loaded.hmac_sha2_256 = nil
local hmac_sha2_256 = require("hmac_sha2_256")

local ALGO_NEGO_NAMELIST = {
  "kex_algorithms",
  "server_host_key_algorithms",
  "encryption_algorithms_client_to_server",
  "encryption_algorithms_server_to_client",
  "mac_algorithms_client_to_server",
  "mac_algorithms_server_to_client",
  "compression_algorithms_client_to_server",
  "compression_algorithms_server_to_client",
  "languages_client_to_server",
  "languages_server_to_client"
}

SSH_Kex = {}
SSH_Kex.__index = SSH_Kex

function SSH_Kex.new(ssh_tran)
  local obj = {}
  obj.algos = {}
  obj.ssh_tran = ssh_tran
  obj.kex_init_server = nil
  obj.kex_init_client = nil
  obj.cookie_server = nil
  obj.cookie_client = component.data.random(16)
  setmetatable(obj, SSH_Kex)
  return obj
end

local function generate_algo_instances(algos)
  for k, v in pairs(algos) do
    if v.name == "ecdh-sha2-nistp256" then
      v.instance = ecdh_sha2_nistp256.new()
    elseif v.name == "ecdsa-sha2-nistp256" then
      v.instance = ecdsa_sha2_nistp256.new()
    elseif v.name == "aes128-ctr" then
      v.instance = aes128_ctr.new()
    elseif v.name == "hmac-sha2-256" then
      v.instance = hmac_sha2_256.new()
    end
  end
end

function SSH_Kex:create_kex_client(kex_content_server)
  self.kex_init_server = kex_content_server
  
  -- Get rid of SSH_MSG_KEXINIT
  kex_content_server = kex_content_server:sub(2)

  self.cookie_server = kex_content_server:sub(1,16)
  kex_content_server = kex_content_server:sub(17)

  -- Convert the server supported algos to 2D array
  local server_list_namelist = {}
  for _, algo_name in ipairs(ALGO_NEGO_NAMELIST) do
    local algos
    algos, kex_content_server = parseNamelist(kex_content_server)
    if self.ssh_tran.debug then
      print("\27[36m" .. algo_name .. ":    " .. "\27[0m" ..  table.concat(algos,","))
    end
    table.insert(server_list_namelist, algos)
  end
  
  -- The client kex payload to server
  local kex_content_client = string.char(SSH_MSG_KEXINIT) .. self.cookie_client

  -- Find match algos between client and server
  for i, client_algos in ipairs(OPENOS_SSH_SUPPORRTED_ALGO) do

    local match_algo_found = false

    if #client_algos == 0 then
      match_algo_found = #server_list_namelist[i] == 0
      self.algos[ALGO_NEGO_NAMELIST[i]] = {name = ""}
    end

    for _, client_algo in ipairs(client_algos) do
      if arrayContains(server_list_namelist[i], client_algo) then
        self.algos[ALGO_NEGO_NAMELIST[i]] = {name = client_algo} 
        match_algo_found = true
        break
      end
    end

    if not match_algo_found then
      error("Unsupported algorithm " .. ALGO_NEGO_NAMELIST[i] .. ": " .. table.concat(server_list_namelist[i],",") .. " required.", 0)
    end

    kex_content_client = kex_content_client .. createNamelist(client_algos)

  end

  --[[                                    No guess kex client        Reserved       --]]
  kex_content_client = kex_content_client .. string.char(0) .. string.pack(">I4", 0)
  self.kex_init_client = kex_content_client

  local guessed_kex_server = string.byte(kex_content_server:sub(1,1))
  local guessed_kex_used_server = (server_list_namelist[1][1] == self.algos.kex_algorithms.name)
  local skip_guessed_kex_server = (guessed_kex_server == 1) and (not guessed_kex_used_server)

  generate_algo_instances(self.algos)

  return kex_content_client, skip_guessed_kex_server

end


function SSH_Kex:receive_kex_server(content)

  -- Get rid of SSH_MSG_KEX_ECDH_REPLY
  content = content:sub(2)
  
  local server_pub_host_key_len = string.unpack(">I4", content:sub(1, 4))
  local server_pub_host_key = content:sub(5, 4 + server_pub_host_key_len)
  content = content:sub(5 + server_pub_host_key_len)

  local server_pubkey_len = string.unpack(">I4", content:sub(1, 4))
  local server_pubkey = content:sub(5, 4 + server_pubkey_len)
  content = content:sub(5 + server_pubkey_len)

  local exchange_hash_sign_len = string.unpack(">I4", content:sub(1, 4))
  local exchange_hash_sign = content:sub(5, 4 + exchange_hash_sign_len)

  assert( #exchange_hash_sign == exchange_hash_sign_len )

  -- Prompt user to store host key if neccessary
  ssh_known_hosts.handle_connect_server_host_key(server_pub_host_key, self.algos["server_host_key_algorithms"].name, self.ssh_tran.host, self.ssh_tran.port)
  
  -- Perform key exchange
  self.algos["kex_algorithms"].instance:perform_exchange(server_pubkey)

  -- Perform exchange hash generation
  self.algos["kex_algorithms"].instance:generate_exchange_hash(
    self.ssh_tran.identify_str_client, self.ssh_tran.identify_str_server,
    self.kex_init_client, self.kex_init_server, server_pub_host_key
  )

  -- Set public server host key
  self.algos["server_host_key_algorithms"].instance:set_pubkey_server(server_pub_host_key)

  local sign_valid = self.algos["server_host_key_algorithms"].instance:verify_sign(
    self.algos["kex_algorithms"].instance.exchange_hash, exchange_hash_sign
  )
  
  if not sign_valid then
    error("Invalid signature on exchanged key hash from the server!", 0)
  elseif self.ssh_tran.debug then
    print("kex_algorithms: Verified exchange hash signature.")
  end

end


function SSH_Kex:encryption_mac_instance_setkey(session_id)
  
  local kex_algo = self.algos["kex_algorithms"].instance
  local enc_algo_c2s = self.algos["encryption_algorithms_client_to_server"].instance
  local enc_algo_s2c = self.algos["encryption_algorithms_server_to_client"].instance
  local mac_algo_c2s = self.algos["mac_algorithms_client_to_server"].instance
  local mac_algo_s2c = self.algos["mac_algorithms_server_to_client"].instance
  
  local init_iv_c2s = kex_algo:get_initial_key("A", session_id, enc_algo_c2s.get_iv_len())
  local init_iv_s2c = kex_algo:get_initial_key("B", session_id, enc_algo_s2c.get_iv_len())
  local enc_key_c2s = kex_algo:get_initial_key("C", session_id, enc_algo_c2s.get_key_len())
  local enc_key_s2c = kex_algo:get_initial_key("D", session_id, enc_algo_s2c.get_key_len())
  local mac_key_c2s = kex_algo:get_initial_key("E", session_id, mac_algo_c2s.get_key_len())
  local mac_key_s2c = kex_algo:get_initial_key("F", session_id, mac_algo_s2c.get_key_len())
  
  enc_algo_c2s:set_key_iv(enc_key_c2s, init_iv_c2s)
  enc_algo_s2c:set_key_iv(enc_key_s2c, init_iv_s2c)
  mac_algo_c2s:set_key(mac_key_c2s)
  mac_algo_s2c:set_key(mac_key_s2c)

end


return SSH_Kex
