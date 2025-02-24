package.loaded.ssh_config = nil
require("ssh_config")

local io = require("io")
local filesystem = require("filesystem")
local component = require("component")
local term = require("term")
local sha256 = require("cryptolib.sha256")

SSH_Known_Host = {}
SSH_Known_Host.__index = SSH_Known_Host

local function retreiveKnownHostKey(host_key_method, host, port)
  local fd = io.open(filesystem.concat(SSH_BASE_FOLDER, "known_hosts"), "r")
  if fd == nil then
    return nil
  end
  for line in fd:lines() do
    local words = {}
    for word in line:gmatch("%S+") do table.insert(words, word) end

    local checkHostPort = host
    if port ~= 22 then
      checkHostPort = checkHostPort .. ":" .. port
    end

    if checkHostPort == words[1] and host_key_method == words[2] then
      local host_key = component.data.decode64(words[3])
      fd:close()
      return host_key
    end
  end
  
  fd:close()
  return nil
end


local function removeKnownHostKey(host_key_method, host, port)
  local fd = io.open(filesystem.concat(SSH_BASE_FOLDER, "known_hosts"), "r")
  if fd == nil then
    return
  end
  
  local newFileContent = ""
  for line in fd:lines() do
    local words = {}
    for word in line:gmatch("%S+") do table.insert(words, word) end

    local checkHostPort = host
    if port ~= 22 then
      checkHostPort = checkHostPort .. ":" .. port
    end

    if checkHostPort ~= words[1] or host_key_method ~= words[2] then
      newFileContent = newFileContent .. line .. "\n"
    end
  end
  
  fd:close()
  
  local fd = io.open(filesystem.concat(SSH_BASE_FOLDER, "known_hosts"), "w")
  fd:write(newFileContent)
  fd:close()

end


local function appendServerHostKey(server_host_key, host_key_method, host, port)
  local hostport = host
  if port ~= 22 then
    hostport = hostport .. ":" .. port
  end
  local fd = io.open(filesystem.concat(SSH_BASE_FOLDER, "known_hosts"), "a")
  
  fd:write(hostport .. " " .. host_key_method .. " " .. component.data.encode64(server_host_key) .. "\n")
  fd:close()
end


function SSH_Known_Host.handle_connect_server_host_key(server_host_key, host_key_method, host, port)
  
  local hostport = host
  if port ~= 22 then
    hostport = hostport .. ":" .. port
  end

  local local_server_host_key = retreiveKnownHostKey(host_key_method, host, port)
  -- If local server host key can't find
  if local_server_host_key == nil or local_server_host_key ~= server_host_key then

    local server_host_key_fingerprint = component.data.encode64(sha256.digest(server_host_key))
    print("The authenticity of host '" .. hostport .. "' can't be established.")
    print(host_key_method:match('([^-]+)'):upper() .. " key fingerprint is SHA256:" .. server_host_key_fingerprint .. ".")
    print("This key is not known by any other names.")
    
    -- TODO?: Add [fingerprint] support
    print("Are you sure you want to continue connecting (yes/No)?")
    local cur_x, cur_y = term.getCursor()
    term.setCursor(cur_x + 55, cur_y - 1)
    local res = io.read()
    
    if res:lower() == "yes" or res:lower() == "y" then
      -- Remove old host key in case of not match
      removeKnownHostKey(host_key_method, host, port)
      -- Append new host key to the file
      appendServerHostKey(server_host_key, host_key_method, host, port)
    else
      error("Host key verification failed.", 0)
    end

  end

end


return SSH_Known_Host
