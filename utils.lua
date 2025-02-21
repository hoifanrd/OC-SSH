local io = require("io")

function parseNamelist(msg)
  local len = string.unpack(">I4", msg:sub(1,4))
  local list = msg:sub(5, 5+len-1)
  local tab_list = {}
  for word in string.gmatch(list, '([^,]+)') do
    table.insert(tab_list, word)
  end
  return tab_list, msg:sub(5+len)
end

function createNamelist(namelist)
  local list = table.concat(namelist, ",")
  local len = string.pack(">I4", #list)
  return len .. list
end

function arrayContains(array, value)
  for i = 1, #array do
    if (array[i] == value) then
      return true
    end
  end
  return false
end


function to_mpint(val)
  -- Format of mpint, if MSB is 1 but it's positive, need add extra 0 byte
  if string.byte(val, 1) >= 128 then
    val = string.char(0) .. val
  end
  return string.pack(">I4", #val) .. val
end


function xor(a, b)

  local result = ""

  for i = 1, math.min(#a, #b) do
      local a_ch = string.byte(a, i, i)
      local b_ch = string.byte(b, i, i)

      local xor_ch = a_ch ~ b_ch

      result = result .. string.char(xor_ch)
  end

  return result
end


function incr_bitstr(val)
  
  local rev_val = string.reverse(val)
  local res = ""
  local addone = true

  while addone and #rev_val > 0 do
    local cur_ch = string.byte(rev_val, 1)
    local new_ch = cur_ch + 1
    if new_ch < 256 then
      addone = false
    else
      new_ch = 0
    end
    res = string.char(new_ch) .. res
    rev_val = rev_val:sub(2)
  end

  return string.reverse(rev_val) .. res

end



function str_to_hex(str)
  local pubHex = ""
  for i = 1, #str do
      local char = str:sub(i, i)
      pubHex = pubHex .. string.format("%02x", string.byte(char))
  end
  return pubHex
end


function write_to_log(str)
  local fd = io.open("log.txt", "a")
  fd:write(str)
  fd:close()
end