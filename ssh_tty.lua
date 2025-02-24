-- https://github.com/oc-ulos/oc-cynosure-2/blob/dev/src/tty.lua#L105
-- Modified by hoifanrd

--[[
    Second vt100 implementation.  Should be fairly compatible with console_codes(5).
    Copyright (C) 2024 ULOS Developers

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
  ]]--

local component = require("component")
local computer = require("computer")
local term = require("term")
local keyboard = require("keyboard")
local unicode = require("unicode")




local function parse_str(str)

  local parsed = {}

  local function parse_unicode(str)
    local utf8_idx = 1
    while #str > 0 do
      local char_len
      local lu_1byte = string.byte(str, 1)
      if (lu_1byte >> 5) == 6 then
        char_len = 2
      elseif (lu_1byte >> 4) == 14 then
        char_len = 3
      elseif (lu_1byte >> 3) == 30 then
        char_len = 4
      else
        char_len = 1
      end
      parsed[utf8_idx] = string.sub(str, 1, char_len)
      str = string.sub(str, char_len + 1)
      utf8_idx = utf8_idx + 1
    end
  end

  parse_unicode(str)

  local function sub(i, j)
    j = j or #parsed
    local res = ""
    for k=i, j do
      res = res .. parsed[k]
    end
    return res
  end

  local function len()
    return #parsed
  end

  return {
    sub = sub,
    len = len
  }

end



local function escape_unicode_sub(str, i, j)

  local utf8_idx = 1
  while utf8_idx < i and #str > 0 do
    local next_byte_idx
    local lu_1byte = string.byte(str, 1)
    if (lu_1byte >> 5) == 6 then
      next_byte_idx = 3
    elseif (lu_1byte >> 4) == 14 then
      next_byte_idx = 4
    elseif (lu_1byte >> 3) == 30 then
      next_byte_idx = 5
    else
      next_byte_idx = 2
    end
    str = string.sub(str, next_byte_idx)
    utf8_idx = utf8_idx + 1
  end

  if #str == 0 or j == nil then
    return str
  end

  local end_idx = 0
  local str_len = #str
  while utf8_idx <= j and end_idx < str_len do
    local next_byte_idx
    local lu_1byte = string.byte(str, end_idx + 1)
    if (lu_1byte >> 5) == 6 then
      next_byte_idx = 2
    elseif (lu_1byte >> 4) == 14 then
      next_byte_idx = 3
    elseif (lu_1byte >> 3) == 30 then
      next_byte_idx = 4
    else
      next_byte_idx = 1
    end
    end_idx = end_idx + next_byte_idx
    utf8_idx = utf8_idx + 1
  end

  return string.sub(str, 1, end_idx)

end




do
  
  k = {}
  
  -- control characters
  local NUL = '\x00'
  local BEL = '\x07'
  local BS  = '\x08'
  local HT  = '\x09'
  local LF  = '\x0a'
  local VT  = '\x0b'
  local FF  = '\x0c'
  local CR  = '\x0d'
  -- UNSUPPORTED: SO, SI
  local SO  = '\x0e'
  local SI  = '\x0f'
  local CAN = '\x18'
  local SUB = '\x1a'
  local ESC = '\x1b'
  -- ignored apparently
  local DEL = '\x7f'
  -- equivalent to esc [
  local CSI = '\xc2\x9B'

  local code_chars = {
    [0x3B] = "OP",
    [0x3C] = "OQ",
    [0x3D] = "OR",
    [0x3E] = "OS",
    [0x3F] = "[15~",
    [0x40] = "[17~",
    [0x41] = "[18~",
    [0x42] = "[19~",
    [0x43] = "[20~",
    [0x44] = "[21~",
    [0x57] = "[23~",
    [0x58] = "[24~"
  }

  local MODE_NORMAL = 0
  local MODE_ESC = 1
  local MODE_CSI = 2
  local MODE_DSAT = 3
  local MODE_CHARSET = 4
  local MODE_G0 = 5
  local MODE_G1 = 6
  local MODE_OSC = 7

  local control_chars = {
    [NUL] = true,
    [BEL] = true,
    [BS] = true,
    [HT] = true,
    [LF] = true,
    [VT] = true,
    [FF] = true,
    [CR] = true,
    [SO] = true,
    [SI] = true,
    [CAN] = true,
    [SUB] = true,
    [ESC] = true,
    [DEL] = true,
    [CSI] = true,
  }

  local scancode_lookups = {
    [200] = "A",
    [208] = "B",
    [205] = "C",
    [203] = "D"
  }

  local colors = {
    0x000000,
    0xaa0000,
    0x00aa00,
    0xaaaa00,
    0x0000aa,
    0xaa00aa,
    0x00aaaa,
    0xaaaaaa,
    -- bright
    0x555555,
    0xff5555,
    0x55ff55,
    0xffff55,
    0x5555ff,
    0xff55ff,
    0x55ffff,
    0xffffff
  }


  local sub, len = escape_unicode_sub, unicode.len
  local function get_iter(parsed_str)
    local n, str_len = 0, parsed_str.len()
    return function()
      n = n + 1
      if n <= str_len then return n, parsed_str.sub(n, n) end
    end
  end

  function k.open_tty(discipline)

    local gpu = term.gpu()
    local _, ori_fg, ori_bg = gpu.get(term.getCursor())

    --[[
    gpu.set = (function(func)
      return function(...)
        write_to_log(string.format("Set coordinate %d, %d with string \"%s\" \n", ...))
        func(...)
      end
    end)(gpu.set)

    gpu.copy = (function(func)
      return function(...)
        write_to_log(string.format("Copy rectangle at coordinate %d, %d; of size %d, %d; to offset %d, %d \n", ...))
        func(...)
      end
    end)(gpu.copy)

    gpu.fill = (function(func)
      return function(...)
        write_to_log(string.format("Fill rectangle at coordinate %d, %d; of size %d, %d; with character \"%s\" \n", ...))
        func(...)
      end
    end)(gpu.fill)
    --]]

    local w, h = gpu.getResolution()
    local mode = MODE_NORMAL
    local seq = {}
    local wbuf, rbuf = "", ""
    local tab_width = 8
    local question = false
    local autocr, reverse, insert, display, mousereport, cursor, altcursor, autowrap
      = true, false, false, false, false, true, false, true
    local cx, cy, scx, scy = term.getCursor()    -- Init cursor to OS term location
    local st, sb = 1, h
    local fg, bg = colors[8], colors[1]
    local save = {fg = fg, bg = bg, autocr = autocr, reverse = reverse, display = display, insert = insert,
      mousereport = mousereport, altcursor = altcursor, cursor = cursor, autowrap = autowrap}
    local save_alt = {st = st, sb = sb, cx = cx, cy = cy, fg = fg, bg = bg, autocr = autocr, reverse = reverse, display = display, insert = insert,
    mousereport = mousereport, altcursor = altcursor, cursor = cursor, autowrap = autowrap}
    local bracketpaste, altbuffer = false, nil
    local cursorvisible = false
    local shouldchange = false
    local keyboards = {}
    local bound_screen = gpu.getScreen()
    local new = {discipline = discipline}

    for _, kbaddr in pairs(component.invoke(gpu.getScreen(), "getKeyboards")) do
      keyboards[kbaddr] = true
    end

    local function cursor_valid()
      return cx >= 1 and cx <= w and cy >= 1 and cy <= h
    end

    local function setcursor(v)
      if cursorvisible ~= v then
        shouldchange = true
        cursorvisible = v
        if cursor_valid() then
          local c, cfg, cbg = gpu.get(cx, cy)
          gpu.setBackground(cfg)
          gpu.setForeground(cbg)
          gpu.set(cx, cy, c)
        end
      end
    end

    -- Fix hoifanrd
    local function scroll(n)
      -- write_to_log(string.format("Scroll for %d lines; st = %d, sb = %d \n", n, st, sb))
      if n < 0 then
        gpu.copy(1, st, w, math.max(0, (sb - st + 1) + n), 0, -n)
        gpu.fill(1, st, w, math.min(sb - st + 1, -n), " ")
      else
        gpu.copy(1, st+n, w, math.max(0, (sb - st + 1) - n), 0, -n)
        gpu.fill(1, sb - n + 1, w, n, " ")
      end
    end

    local function corral()
      cx = math.max(1, cx)
      if cx > w and autowrap then
        cx = 1
        cy = cy + 1
      end
      if cy > sb then
        scroll(cy - sb)
        cy = sb
      elseif cy < st then
        scroll(-(st - cy))
        cy = st
      end
    end

    local function switch_alt()
      save_alt = {st = st, sb = sb, cx = cx, cy = cy, fg = fg, bg = bg, autocr = autocr, reverse = reverse, display = display, insert = insert,
        mousereport = mousereport, altcursor = altcursor, cursor = cursor, autowrap = autowrap}
      altbuffer = gpu.allocateBuffer()
      gpu.bitblt(1)
      gpu.fill(1, 1, w, h, " ")
    end

    local function switch_main()
      cx, cy, st, sb = save_alt.cx, save_alt.cy, save_alt.st, save_alt.sb
      fg, bg = save_alt.fg, save_alt.bg
      autocr, reverse, display, insert = save_alt.autocr, save_alt.reverse, save_alt.display, save_alt.insert
      mousereport, altcursor, cursor, autowrap = save_alt.mousereport, save_alt.altcursor, save_alt.cursor, save_alt.autowrap
      gpu.setActiveBuffer(altbuffer)
      gpu.bitblt()
      gpu.freeBuffer(altbuffer)
    end

    local function clamp()
      cx, cy = math.min(w, math.max(1, cx)), math.min(h, math.max(1, cy))
    end

    local function flush()

      -- Add unicode malformed check
      local malformed = false
      local valid_wbuf = wbuf

      local last_unicode = sub(valid_wbuf, len(valid_wbuf))
      local lu_1byte = string.byte(last_unicode, 1)
      if #last_unicode == 1 then
        malformed = (lu_1byte >> 7) ~= 0
      elseif #last_unicode == 2 then
        malformed = (lu_1byte >> 5) ~= 6
      elseif #last_unicode == 3 then
        malformed = (lu_1byte >> 4) ~= 14
      elseif #last_unicode == 4 then
        malformed = (lu_1byte >> 3) ~= 30
      end

      if malformed then
        valid_wbuf = sub(valid_wbuf, 1, len(valid_wbuf) - 1)
      end
      wbuf = string.sub(wbuf, #valid_wbuf + 1)

      gpu.setForeground(reverse and bg or fg)
      gpu.setBackground(reverse and fg or bg)
      while #valid_wbuf > 0 and autowrap do
        local towrite = sub(valid_wbuf, 1, w-cx+1)
        valid_wbuf = sub(valid_wbuf, #towrite+1)
        if insert then
          gpu.copy(cx, cy, w, 1, len(towrite), 0)
        end
        corral()
        -- write_to_log("Writing at line " .. cy .. "\n")
        gpu.set(cx, cy, towrite)
        cx = cx + len(towrite)
      end
      if new.discipline and #rbuf > 0 then
        new.discipline:processInput(rbuf)
        rbuf = ""
      end
    end

    local function write(_, str)
      if #str == 0 then return end

      setcursor(false)

      local pi = mode == MODE_NORMAL and 1 or -1  -- Fix hoifanrd
      local parsed_str = parse_str(str)
      for i, c in get_iter(parsed_str) do

        if shouldchange then                      -- Fix hoifanrd
          gpu.setForeground(reverse and bg or fg)
          gpu.setBackground(reverse and fg or bg)
          shouldchange = false
        end

        if control_chars[c] then
          if pi > 0 then
            wbuf = wbuf .. parsed_str.sub(pi, i-1)
            flush()
            pi = -1
          end
          -- control characters are always processed, even in the middle of a sequence
          if c == BEL then
            
            if mode == MODE_OSC then
              -- ???
              mode = MODE_NORMAL
            else
              computer.beep()
            end

          elseif c == BS then
            cx = cx - 1
            corral()
          elseif c == HT then
            cx = tab_width * math.floor((cx + tab_width + 1) / tab_width) - 1
            corral()
          elseif c == LF or c == VT or c == FF then
            if autocr then cx = 1 end
            cy = cy + 1
            corral()
          elseif c == CR then
            cx = 1
          elseif c == CAN or c == SUB then
            mode = MODE_NORMAL
          elseif c == ESC then -- start new ESC-sequence
            seq = {}
            mode = MODE_ESC
          elseif c == CSI then -- start new CSI-sequence (ESC [)
            seq = {}
            question = false
            mode = MODE_CSI
          end

        elseif mode == MODE_ESC then
          if c == "[" then
            mode = MODE_CSI
            question = false
          elseif c == "c" then -- RIS / reset
            fg, bg = colors[8], colors[1]
            autocr, reverse, insert, display, mousereport, cursor, altcursor, autowrap
              = false, false, false, false, false, true, false, true
          elseif c == "D" then -- IND / line feed
            cy = cy + 1
            corral()
          elseif c == "E" then -- NEL / newline
            cy = cy + 1
            cx = 1
            corral()
          elseif c == "F" then -- cursor to lower left of screen
            cx, cy = 1, h
          elseif c == "H" then -- HTS / set tab stop at current column
            error("TODO: ESC H")
          elseif c == "M" then -- RI / reverse linefeed
            cy = cy - 1
            corral()
          elseif c == "Z" then -- DECID / DEC private identification.  return ESC [ ? 6 c (VT102)
            rbuf = rbuf .. ESC .. "[?6c"
          elseif c == "7" then -- DECSC / save current state (cursor, attributes, charsets)   https://vt100.net/docs/vt510-rm/DECSC.html
            save = {fg = fg, bg = bg, autocr = autocr, reverse = reverse, display = display, insert = insert,
              mousereport = mousereport, altcursor = altcursor, cursor = cursor, autowrap = autowrap}
          elseif c == "8" then -- DECRC / restore last ESC 7 state
            fg, bg = save.fg, save.bg
            autocr, reverse, display, insert = save.autocr, save.reverse, save.display, save.insert
            mousereport, altcursor, cursor, autowrap = save.mousereport, save.altcursor, save.cursor, save.autowrap
          elseif c == "%" then -- start sequence selecting character set
            mode = MODE_CHARSET
          elseif c == "#" then -- start DECALN
            mode = MODE_DSAT
          elseif c == "(" then -- define G0
            mode = MODE_G0 -- TODO
          elseif c == ")" then -- define G1
            mode = MODE_G1 -- TODO
          elseif c == ">" then -- DECPNM / set numeric keypad mode
            -- TODO
          elseif c == "=" then -- DECPAM / set application keypad mode
            -- TODO
          elseif c == "]" then -- OSC / operating system command
            mode = MODE_OSC
          end

        elseif mode == MODE_CSI then
          if c == "?" then
            if #seq > 0 or question then
              mode = MODE_NORMAL
              question = false
            else
              question = true
            end
          elseif c == "@" then -- ICH / insert blank characters
            if seq[1] and seq[1] > 0 then
              gpu.copy(cx, cy, w, 1, seq[1], 0)
              gpu.fill(cx, cy, seq[1], 1, " ")
            end
          elseif c == "A" then -- CUU / cursor up
            cy = cy - (seq[1] or 1)
            clamp()
          elseif c == "B" or c == "e" then -- CUD, VPR / cursor down
            cy = cy + (seq[1] or 1)
            clamp()
          elseif c == "C" or c == "a" then -- CUF, HPR / cursor right
            cx = cx + (seq[1] or 1)
            clamp()
          elseif c == "D" then -- CUB / cursor left
            cx = cx - (seq[1] or 1)
            clamp()
          elseif c == "E" then -- CNL / cursor down N rows to column 1
            cx = 1
            cy = cy - (seq[1] or 1)
            clamp()
          elseif c == "F" then -- CPL / cursor up N rows to column 1
            cx = 1
            cy = cy + (seq[1] or 1)
            clamp()
          elseif c == "G" or c == "`" then -- CHA, HPA / cursor to column
            cx = (seq[1] or 1)
            clamp()
          elseif c == "H" or c == "f" then -- CUP, HVP / cursor to row, column
            cy, cx = seq[1] or 1, seq[3] or 1
            clamp()
          elseif c == "J" then -- ED / erase display
            local m = seq[1] or 0
            if m == 0 then
              -- erase from cursor to end
              gpu.fill(cx, cy, w, 1, " ")
              gpu.fill(1, cy+1, w, h, " ")
            elseif m == 1 then
              -- erase from start to cursor
              gpu.fill(1, 1, w, cy-1, " ")
              gpu.fill(1, cy, cx, 1, " ")
            elseif m == 2 or m == 3 then
              -- erase whole screen
              gpu.fill(1, 1, w, h, " ")
            end
          elseif c == "K" then -- EL / erase line
            local m = seq[1] or 0
            if m == 0 then -- erase from cursor to end
              gpu.fill(cx, cy, w, 1, " ")
            elseif m == 1 then -- erase from start to cursor
              gpu.fill(1, cy, cx, 1, " ")
            elseif m == 2 then -- erase whole line
              gpu.fill(1, cy, w, 1, " ")
            end
          elseif c == "L" then -- IL / insert blank lines
            local n = seq[1] or 1
            gpu.copy(1, cy, w, h, 0, n)
            gpu.fill(1, cy, w, n, " ")
          elseif c == "M" then -- DL / delete lines
            local n = seq[1] or 1
            gpu.copy(1, cy, w, h, 0, -n)
            gpu.fill(1, h-n, w, n, " ")
          elseif c == "P" then -- DCH / delete characters
            local n = seq[1] or 1
            gpu.copy(cx, cy, w, 1, -n, 0)
          elseif c == "S" then -- not in console_codes(4) / scroll down
            scroll(seq[1] or 1)
          elseif c == "T" then -- not in console_codes(4) / scroll up
            scroll(-(seq[1] or 1))
          elseif c == "X" then -- ECH / erase characters
            local n = seq[1] or 1
            gpu.fill(cx, cy, n, 1, " ")

          -- ESC [ a identical to ESC [ C, see above
          elseif c == "c" then -- DA / answer "VT102"
            rbuf = rbuf .. ESC .. "?6c"
          elseif c == "d" then -- VPA / move cursor to row, current column
            cy = seq[1] or 1
            clamp()
          -- e / VPR identical to B
          -- f / HVP identical to H
          elseif c == "g" then -- TBC / clear current tab stop
            -- TODO
            -- if arg == 3 clear ALL tab stops
          elseif c == "h" or c == "l" then -- SM, RM / set mode, reset mode
            local set = c == "h"
            if question then -- DEC private modes
              for i=1, #seq, 2 do
                if seq[i] == 1 then -- DECCKM / cursor keys send ESC O instead of ESC [
                  altcursor = set
                -- DECCOLM / 80/132 col switch not implemented
                -- DECSCNM / reverse video mode not implemented
                elseif seq[i] == 6 then -- DECOM / cursor addressing relative to scroll region
                  -- TODO
                elseif seq[i] == 7 then -- DECAWM / autowrap
                  autowrap = set
                elseif seq[i] == 9 then -- X10 mouse reporting
                  mousereport = set and 1 or 0
                elseif seq[i] == 25 then -- DECTECM / set cursor visible
                  cursor = set
                elseif seq[i] == 1000 then -- X11 mouse reporting
                  mousereport = set and 2 or 0
                elseif seq[i] == 1049 then  -- Alternative screen buffer
                  local alt_used = arrayContains(gpu.buffers(), altbuffer)
                  if set and not alt_used then
                    switch_alt()
                  elseif alt_used then
                    switch_main()
                  end
                elseif seq[i] == 2004 then  -- Bracket paste mode
                  bracketpaste = set
                end
              end

            else -- ECMA-48 modes
              for i=1, #seq, 2 do
                if seq[i] == 3 then -- DECCRM / display control characters
                  display = set
                elseif seq[i] == 4 then -- set insert mode
                  insert = set
                elseif seq[i] == 20 then -- autocr
                  autocr = set
                end
              end
            end
          elseif c == "m" then -- SGR / set attributes
            if not seq[1] then seq[1] = 0 end
            for i=1, #seq, 2 do
              -- only implement a subset of these that it makes sense to
              if seq[i] == 0 then -- reset
                fg, bg = colors[8], colors[1]
                reverse = false
              elseif seq[i] == 7 then -- reverse
                reverse = true
              elseif seq[i] == 27 then -- unset reverse
                reverse = false
              elseif seq[i] > 29 and seq[i] < 38 then -- foreground
                fg = colors[seq[i] - 29]
                shouldchange = true
              elseif seq[i] > 39 and seq[i] < 48 then -- background
                bg = colors[seq[i] - 39]
                shouldchange = true
                -- TODO: 38/48 rgb color support?
              elseif seq[i] == 39 then -- default fg
                fg = colors[8]
                shouldchange = true
              elseif seq[i] == 49 then -- default bg
                bg = colors[1]
                shouldchange = true
              elseif seq[i] > 89 and seq[i] < 98 then -- bright foreground
                fg = colors[seq[i] - 81]
                shouldchange = true
              elseif seq[i] > 99 and seq[i] < 108 then -- bright background
                bg = colors[seq[i] - 91]
                shouldchange = true
              end
            end
          elseif c == "n" then -- DSR / status report
            for i=1, #seq, 2 do
              if seq[i] == 5 then -- DSR / device status report
                rbuf = rbuf .. ESC .. "[0n" -- Terminal OK
              elseif seq[i] == 6 then -- CPR / cursor position report
                rbuf = rbuf .. string.format("%s[%d;%dR", ESC, cy, cx)
              end
            end
          -- no [ q / DECLL, keyboard LEDs not implemented
          elseif c == "r" then -- DECSTBM / set scrolling region
            st, sb = seq[1] or 1, seq[3] or h                      -- Fix hoifanrd
          elseif c == "s" then -- ? / save cursor position
            scx, scy = cx, cy
          elseif c == "u" then -- ? / restore cursor position
            cx, cy = scx or cx, scy or cy
          -- HPA identical to CHA/G

          -- CSI [ c and ESC [ [ c are ignored, to ignore echoed function keys
          elseif c == "[" then
            seq = "["
          elseif seq == "[" then
            mode = MODE_NORMAL

          elseif c == ";" then
            if seq[#seq] == ";" then
              seq[#seq+1] = 0
            end
            seq[#seq+1] = ";"
          elseif tonumber(c) then
            if seq[#seq] == ";" then
              seq[#seq+1] = tonumber(c)
            else
              seq[math.max(1, #seq)] = (seq[#seq] or 0) * 10 + tonumber(c)
            end
          end

          if c ~= ";" and c ~= "?" and not tonumber(c) then
            mode = MODE_NORMAL
          end

        elseif mode == MODE_NORMAL then
          if pi < 1 then
            pi = i
          end

        elseif mode == MODE_OSC then
          
          if c == ";" then
            seq[#seq+1] = ";"
          elseif tonumber(c) then
            if not seq[#seq] or type(seq[#seq]) == "number" then
              seq[math.max(1, #seq)] = (seq[#seq] or 0) * 10 + tonumber(c)
            else
              seq[#seq+1] = c
            end
          else
            seq[#seq+1] = c
          end

        elseif mode == MODE_G0 then
          mode = MODE_NORMAL -- TODO

        elseif mode == MODE_G1 then
          mode = MODE_NORMAL -- TODO

        elseif mode == MODE_CHARSET then
          mode = MODE_NORMAL -- TODO

        elseif mode == MODE_DSAT then
          if c == "8" then
            gpu.fill(1, 1, w, h, "E")
          end
          mode = MODE_NORMAL
        end
      end

      if pi > 0 then
        wbuf = wbuf .. parsed_str.sub(pi, parsed_str.len())
      end

      flush()

      if mode == MODE_NORMAL and cursor then
        setcursor(true)
      end

    end

    new.write = write
    new.flush = function() end

    new.handle_key_down = function(_, kbd, char, code)
      if not keyboards[kbd] then return end
      if not new.discipline then return end

      local to_buffer
      if scancode_lookups[code] then
        local c = scancode_lookups[code]
        local interim = altcursor and "O" or "["
        to_buffer = ESC .. interim .. c

      elseif code_chars[code] then
        to_buffer = ESC .. code_chars[code]
      elseif char > 0 then
        if keyboard.isAltDown() then
          to_buffer = ESC .. string.char(char)
        else
          to_buffer = string.char(char)
        end
      end

      if to_buffer then
        new.discipline:processInput(to_buffer)
      end
    end

    new.handle_clipboard = function(_, kbd, str)
      if not keyboards[kbd] then return end
      if bracketpaste then
        str = ESC .. "[200~" .. str .. ESC .. "[201~"
      end
      new.discipline:processInput(str)
    end

    new.handle_mouse_scroll = function(_, scrn, x, y, dir)
      if scrn ~= bound_screen then return end
      if mousereport then
        local code = dir > 0 and 0 or 1
        local to_buf = ESC .. "[M" .. string.char(code+64+32, x+32, y+32)
        new.discipline:processInput(to_buf)
      end
    end

    new.handle_mouse_click = function(_, scrn, x, y, btn)
      if scrn ~= bound_screen then return end
      if mousereport then
        local to_buf = ESC .. "[M" .. string.char(btn+32, x+32, y+32)
        new.discipline:processInput(to_buf)
      end
    end

    new.handle_mouse_release = function(_, scrn, x, y, btn)
      if scrn ~= bound_screen then return end
      if mousereport then
        local to_buf = ESC .. "[M" .. string.char(3+32, x+32, y+32)
        new.discipline:processInput(to_buf)
      end
    end

    new.close_tty = function()
      if arrayContains(gpu.buffers(), altbuffer) then
        switch_main()
      end
      clamp()
      setcursor(false)
      term.setCursor(cx, cy)
      gpu.setForeground(ori_fg)
      gpu.setBackground(ori_bg)
      term.write("\n\n")
    end

    return new
  end


  return k

end
