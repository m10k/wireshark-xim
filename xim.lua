-- xim.lua - Wireshark dissector for the X Input Method protocol
-- Copyright (C) 2025 Matthias Kruk
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published
-- by the Free Software Foundation; either version 3, or (at your
-- option) any later version.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; see the file COPYING.  If not, write to the
-- Free Software Foundation, Inc., 59 Temple Place - Suite 330,
-- Boston, MA 02111-1307, USA.

 xim_opcodes = {
   [1]  = "XIM_CONNECT",
   [2]  = "XIM_CONNECT_REPLY",
   [3]  = "XIM_DISCONNECT",
   [4]  = "XIM_DISCONNECT_REPLY",

   [10] = "XIM_AUTH_REQUIRED",
   [11] = "XIM_AUTH_REPLY",
   [12] = "XIM_AUTH_NEXT",
   [13] = "XIM_AUTH_SETUP",
   [14] = "XIM_AUTH_NG",

   [20] = "XIM_ERROR",

   [30] = "XIM_OPEN",
   [31] = "XIM_OPEN_REPLY",
   [32] = "XIM_CLOSE",
   [33] = "XIM_CLOSE_REPLY",
   [34] = "XIM_REGISTER_TRIGGERKEYS",
   [35] = "XIM_TRIGGER_NOTIFY",
   [36] = "XIM_TRIGGER_NOTIFY_REPLY",
   [37] = "XIM_SET_EVENT_MASK",
   [38] = "XIM_ENCODING_NEGOTIATION",
   [39] = "XIM_ENCODING_NEGOTIATION_REPLY",
   [40] = "XIM_QUERY_EXTENSION",
   [41] = "XIM_QUERY_EXTENSION_REPLY",
   [42] = "XIM_SET_IM_VALUES",
   [43] = "XIM_SET_IM_VALUES_REPLY",
   [44] = "XIM_GET_IM_VALUES",
   [45] = "XIM_GET_IM_VALUES_REPLY",

   [50] = "XIM_CREATE_IC",
   [51] = "XIM_CREATE_IC_REPLY",
   [52] = "XIM_DESTROY_IC",
   [53] = "XIM_DESTROY_IC_REPLY",
   [54] = "XIM_SET_IC_VALUES",
   [55] = "XIM_SET_IC_VALUES_REPLY",
   [56] = "XIM_GET_IC_VALUES",
   [57] = "XIM_GET_IC_VALUES_REPLY",
   [58] = "XIM_SET_IC_FOCUS",
   [59] = "XIM_UNSET_IC_FOCUS",
   [60] = "XIM_FORWARD_EVENT",
   [61] = "XIM_SYNC",
   [62] = "XIM_SYNC_REPLY",
   [63] = "XIM_COMMIT",
   [64] = "XIM_RESET_IC",
   [65] = "XIM_RESET_IC_REPLY",

   [70] = "XIM_GEOMETRY",
   [71] = "XIM_STR_CONVERSION",
   [72] = "XIM_STR_CONVERSION_REPLY",
   [73] = "XIM_PREEDIT_START",
   [74] = "XIM_PREEDIT_START_REPLY",
   [75] = "XIM_PREEDIT_DRAW",
   [76] = "XIM_PREEDIT_CARET",
   [77] = "XIM_PREEDIT_CARET_REPLY",
   [78] = "XIM_PREEDIT_DONE",
   [79] = "XIM_STATUS_START",
   [80] = "XIM_STATUS_DRAW",
   [81] = "XIM_STATUS_DONE",
   [82] = "XIM_PREEDITSTATE"
}

xim_errors = {
   [1]   = "BadAlloc",
   [2]   = "BadStyle",
   [3]   = "BadClientWindow",
   [4]   = "BadFocusWindow",
   [5]   = "BadArea",
   [6]   = "BadSpotLocation",
   [7]   = "BadColormap",
   [8]   = "BadAtom",
   [9]   = "BadPixel",
   [10]  = "BadPixmap",
   [11]  = "BadName",
   [12]  = "BadCursor",
   [13]  = "BadProtocol",
   [14]  = "BadForeground",
   [15]  = "BadBackground",
   [16]  = "LocaleNotSupported",

   [999] = "BadSomething"
}

xim_byte_orders = {
   ["l"] = "little endian",
   ["B"] = "big endian"
}

fields = {
   ["xim.major_opcode"]                = ProtoField.new("major-opcode",
							"xim.major_opcode",
							ftypes.UINT8, xim_opcodes),
   ["xim.minor_opcode"]                = ProtoField.new("minor-opcode",
							"xim.minor_opcode",
							ftypes.UINT8),
   ["xim.length"]                      = ProtoField.new("length",
							"xim.length",
							ftypes.UINT16),
   ["xim.im"]                          = ProtoField.new("input-method-ID",
							"xim.im",
							ftypes.UINT16),
   ["xim.ic"]                          = ProtoField.new("input-context-ID",
							"xim.ic",
							ftypes.UINT16),

   ["xim.connect.byte_order"]          = ProtoField.new("byte-order",
							"xim.connect.byte_order",
							ftypes.CHAR),
   ["xim.connect.unused"]              = ProtoField.new("unused",
							"xim.connect.unused",
							ftypes.UINT8),
   ["xim.connect.major_version"]       = ProtoField.new("major-version",
							"xim.connect.major_version",
							ftypes.UINT16),
   ["xim.connect.minor_version"]       = ProtoField.new("minor-version",
							"xim.connect.minor_version",
							ftypes.UINT16),
   ["xim.connect.auth_protos_count"]   = ProtoField.new("auth-protos-count",
							"xim.connect.auth_protos_count",
							ftypes.UINT16),
   ["xim.connect.auth_protos_names"]   = ProtoField.new("auth-protos-names",
							"xim.connect.auth_protos_names",
							ftypes.UINT8),

   ["xim.connect_reply.major_version"] = ProtoField.new("major-version",
							"xim.connect_reply.major_version",
							ftypes.UINT16),
   ["xim.connect_reply.minor_version"] = ProtoField.new("minor-version",
							"xim.connect_reply.minor_version",
							ftypes.UINT16),

   ["xim.error.flag"]                  = ProtoField.new("flag",
							"xim.error.flag",
							ftypes.UINT16),
   ["xim.error.code"]                  = ProtoField.new("error-code",
							"xim.error.code",
							ftypes.UINT16),
   ["xim.error.detail_length"]         = ProtoField.new("detail-length",
							"xim.error.detail_length",
							ftypes.UINT16),
   ["xim.error.detail_type"]           = ProtoField.new("detail-type",
							"xim.error.detail_type",
							ftypes.UINT16),
   ["xim.error.detail"]                = ProtoField.new("detail",
							"xim.error.detail",
							ftypes.STRING),

   ["xim.commit.flag"]                 = ProtoField.new("flag",
							"xim.commit.flag",
							ftypes.UINT16),
   ["xim.commit.unused"]               = ProtoField.new("unused",
							"xim.commit.unused",
							ftypes.UINT16),
   ["xim.commit.keysym"]               = ProtoField.new("keysym",
							"xim.commit.keysym",
							ftypes.UINT32),
   ["xim.commit.string_length"]        = ProtoField.new("string-length",
							"xim.commit.string_length",
							ftypes.UINT16),
   ["xim.commit.string_data"]          = ProtoField.new("string-data",
							"xim.commit.string_data",
							ftypes.STRING),

   ["xim.forward_event.flag"]          = ProtoField.new("flag",
							"xim.forward_event.flag",
							ftypes.UINT16),
   ["xim.forward_event.serial"]        = ProtoField.new("serial-number",
							"xim.forward_event.serial",
							ftypes.UINT16),
   ["xim.forward_event.type"]          = ProtoField.new("type",
							"xim.forward_event.type",
							ftypes.UINT8),
   ["xim.forward_event.detail"]        = ProtoField.new("detail",
							"xim.forward_event.detail",
							ftypes.UINT8),
   ["xim.forward_event.seq"]           = ProtoField.new("sequence-number",
							"xim.forward_event.seq",
							ftypes.UINT16),
   ["xim.forward_event.time"]          = ProtoField.new("time",
							"xim.forward_event.time",
							ftypes.UINT32),
   ["xim.forward_event.root"]          = ProtoField.new("root-window",
							"xim.forward_event.root",
							ftypes.UINT32),
   ["xim.forward_event.window"]        = ProtoField.new("event-window",
							"xim.forward_event.window",
							ftypes.UINT32),
   ["xim.forward_event.child"]         = ProtoField.new("child",
							"xim.forward_event.child",
							ftypes.UINT32),
   ["xim.forward_event.root_x"]        = ProtoField.new("root-x",
							"xim.forward_event.root_x",
							ftypes.INT16),
   ["xim.forward_event.root_y"]        = ProtoField.new("root-y",
							"xim.forward_event.root_y",
							ftypes.INT16),
   ["xim.forward_event.event_x"]       = ProtoField.new("event-x",
							"xim.forward_event.event_x",
							ftypes.INT16),
   ["xim.forward_event.event_y"]       = ProtoField.new("event-y",
							"xim.forward_event.event_y",
							ftypes.INT16),
   ["xim.forward_event.state"]         = ProtoField.new("state",
							"xim.forward_event.state",
							ftypes.UINT16),
   ["xim.forward_event.same_screen"]   = ProtoField.new("same-screen",
							"xim.forward_event.same_screen",
							ftypes.UINT8),
   ["xim.event.unused"]                = ProtoField.new("unused",
							"xim.forward_event.unused",
							ftypes.UINT8),

   ["xim.get_im_values.length"]        = ProtoField.new("attribute-id-list-length",
							"xim.get_im_values.length",
							ftypes.UINT16),
   ["xim.get_im_values.ids"]           = ProtoField.new("attribute-id-list",
							"xim.get_im_values.ids",
							ftypes.BYTES),

   ["xim.get_ic_values.length"]        = ProtoField.new("attribute-id-list-length",
							"xim.get_ic_values.length",
							ftypes.UINT16),
   ["xim.get_ic_values.list"]          = ProtoField.new("attribute-id-list",
							"xim.get_ic_values.list",
							ftypes.BYTES),

   ["xim.open.locale_length"]          = ProtoField.new("locale-length",
							"xim.open.locale_length",
							ftypes.UINT8),
   ["xim.open.locale_name"]            = ProtoField.new("locale-name",
							"xim.open.locale_name",
							ftypes.STRING),

   ["xim.open_reply.im_attrs_length"]  = ProtoField.new("im-attrs-length",
							"xim.open_reply.im_attrs_length",
							ftypes.UINT16),
   ["xim.open_reply.im_attrs"]         = ProtoField.new("im-attrs",
							"xim.open_reply.im_attrs",
							ftypes.BYTES),
   ["xim.open_reply.ic_attrs_length"]  = ProtoField.new("ic-attrs-length",
							"xim.open_reply.ic_attrs_length",
							ftypes.UINT16),
   ["xim.open_reply.ic_attrs"]         = ProtoField.new("ic-attrs",
							"xim.open_reply.ic_attrs",
							ftypes.BYTES),
   ["xim.open_reply.unused"]           = ProtoField.new("unused",
							"xim.open_reply.unused",
							ftypes.UINT16),

   ["xim.query_extension.length"]      = ProtoField.new("length",
							"xim.query_extension.length",
							ftypes.UINT16),
   ["xim.query_extension.extensions"]  = ProtoField.new("extensions",
							"xim.query_extension.extensions",
							ftypes.BYTES),

   ["xim.query_extension_reply.length"]     = ProtoField.new("length",
							     "xim.query_extension_reply.length",
							     ftypes.UINT16),
   ["xim.query_extension_reply.extensions"] = ProtoField.new("extensions",
							     "xim.query_extension_reply.extensions",
							     ftypes.BYTES),

   ["xim.encoding_negotiation.named_length"] = ProtoField.new("named-length",
							      "xim.encoding_negotiation.named_length",
							      ftypes.UINT16),
   ["xim.encoding_negotiation.named"] = ProtoField.new("named",
						       "xim.encoding_negotiation.named",
						       ftypes.BYTES),
   ["xim.encoding_negotiation.detail_length"] = ProtoField.new("detailed-length",
							       "xim.encoding_negotiation.detail_length",
							       ftypes.UINT16),
   ["xim.encoding_negotiation.detail"] = ProtoField.new("detail",
							"xim.encoding_negotiation.detail",
							ftypes.BYTES),

   ["xim.encoding_negotiation_reply.category"] = ProtoField.new("category",
								"xim.encoding_negotiation_reply.category",
								ftypes.UINT16),
   ["xim.encoding_negotiation_reply.encoding"] = ProtoField.new("encoding",
								"xim.encoding_negotiation_reply.encoding",
								ftypes.INT16),

   ["xim.create_ic.attrs_length"]       = ProtoField.new("attribute-list-length",
							 "xim.create_ic.attrs_length",
							 ftypes.UINT16),
   ["xim.create_ic.attrs"] = ProtoField.new("attribute-list",
					    "xim.create_ic.attrs",
					    ftypes.BYTES)

}

xim = Proto("xim", "X Input Method Protocol")
xim.fields = fields
endians = {}
attribute_names = {}

local tcp_stream = Field.new("tcp.stream")

function insert_field(tree, field, buffer, extra)
   local node
   local endian
   local stream

   stream = assert(tonumber(tostring(tcp_stream())))
   endian = endians[stream]

   if endian == "B" then
      node = tree:add(fields[field], buffer)
   else
      node = tree:add_le(fields[field], buffer)
   end

   if extra ~= nil then
      node:append_text(" (" .. extra .. ")")
   end

   return node
end

function insert_raw(tree, buffer, text)
   return tree:add(xim, buffer, text)
end

function dissect_XIM_CONNECT(buffer, pinfo, tree, endian)
   insert_field(tree, "xim.connect.byte_order",        buffer(0, 1), xim_byte_orders[endian])
   insert_field(tree, "xim.connect.unused",            buffer(1, 1))
   insert_field(tree, "xim.connect.major_version",     buffer(2, 2))
   insert_field(tree, "xim.connect.minor_version",     buffer(4, 2))
   insert_field(tree, "xim.connect.auth_protos_count", buffer(6, 2))

   if buffer:len() > 8 then
      insert_field(tree, "xim.connect.auth_protos_names", buffer(8, -1))
   end
end

function dissect_XIM_CONNECT_REPLY(buffer, pinfo, tree, endian)
   insert_field(tree, "xim.connect_reply.major_version", buffer(0, 2))
   insert_field(tree, "xim.connect_reply.minor_version", buffer(2, 2))
end

function dissect_XIM_OPEN(buffer, pinfo, tree, endian)
   local locale_len
   local locale_name

   locale_len = buffer(0, 1):uint()

   insert_field(tree, "xim.open.locale_length", buffer(0, 1))

   if locale_len > 0 then
      if locale_len > buffer:len() then
	 locale_len = buffer:len()
      end

      insert_field(tree, "xim.open.locale_name", buffer(1, locale_len))
   end
end

function Pad(length)
   return (4 - (length % 4)) % 4
end

function set_attribute_name(imic, id, name)
   local stream
   local idx

   stream = assert(tostring(tcp_stream()))
   idx = stream .. "/" .. imic .. "/" .. id
   attribute_names[idx] = name
end

function get_attribute_name(imic, id)
   local stream
   local idx

   stream = assert(tostring(tcp_stream()))
   idx = stream .. "/" .. imic .. "/" .. id

   return attribute_names[idx]
end

function dissect_IMATTR(buffer, tree)
   local attr
   local n
   local p
   local id
   local name

   n = get_data(buffer, 4, 2)
   p = Pad(2 + n)

   id = get_data(buffer, 0, 2)
   name = buffer(6, n):string()

   attr = tree:add(xim, buffer(0, 6 + n + p), "XIMATTR")
   insert_raw(attr, buffer(0,     2), "id: "     .. id)
   insert_raw(attr, buffer(2,     2), "type: "   .. get_data(buffer, 2, 2))
   insert_raw(attr, buffer(4,     2), "length: " .. get_data(buffer, 4, 2))
   insert_raw(attr, buffer(6,     n), "name: "   .. name)
   if p > 0 then
      insert_raw(attr, buffer(6 + n, p), "padding")
   end

   set_attribute_name("XIM", id, name)

   return 6 + n + p
end

function dissect_ICATTR(buffer, tree)
   local attr
   local n
   local p
   local id
   local name

   n = get_data(buffer, 4, 2)
   p = Pad(2 + n)

   id = get_data(buffer, 0, 2)
   name = buffer(6, n):string()

   attr = tree:add(xim, buffer(0, 6 + n + p), "ATTR")
   insert_raw(attr, buffer(0,     2), "id: "     .. id)
   insert_raw(attr, buffer(2,     2), "type: "   .. get_data(buffer, 2, 2))
   insert_raw(attr, buffer(4,     2), "length: " .. get_data(buffer, 4, 2))
   insert_raw(attr, buffer(6,     n), "name: "   .. name)
   if p > 0 then
      insert_raw(attr, buffer(6 + n, p), "padding")
   end

   set_attribute_name("XIC", id, name)

   return 6 + n + p
end

function dissect_XIM_OPEN_REPLY(buffer, pinfo, tree, endian)
   local i
   local n
   local m
   local subtree

   n = get_data(buffer, 2, 2)
   m = get_data(buffer, 4 + n, 2)

   insert_field(tree, "xim.im",                         buffer(0, 2))
   insert_field(tree, "xim.open_reply.im_attrs_length", buffer(2, 2))

   subtree = tree:add(fields["xim.open_reply.im_attrs"], buffer(4, n), "im-attrs")
   i = 0
   while i < n do
      i = i + dissect_IMATTR(buffer(4 + i, n - i), subtree)
   end

   insert_field(tree, "xim.open_reply.ic_attrs_length", buffer(4 + n,     2))
   insert_field(tree, "xim.open_reply.unused",          buffer(4 + n + 2, 2))

   subtree = tree:add(fields["xim.open_reply.ic_attrs"], buffer(4 + n + 4, m), "ic-attrs")
   i = 0
   while i < m do
      i = i + dissect_ICATTR(buffer(4 + n + 4 + i, m - i), subtree)
   end
end

function dissect_XIM_ERROR(buffer, pinfo, tree, endian)
   local len
   local error_name

   insert_field(tree, "xim.im",                  buffer(0, 2))
   insert_field(tree, "xim.ic",                  buffer(2, 2))
   insert_field(tree, "xim.error.flag",          buffer(4, 2))
   insert_field(tree, "xim.error.code",          buffer(6, 2))
   insert_field(tree, "xim.error.detail_length", buffer(8, 2))
   insert_field(tree, "xim.error.detail_type",   buffer(10, 2))
   len = get_data(buffer, 8, 2)

   if len > 0 then
      if len > buffer:len() - 12 then
	 len = buffer:len() - 12
      end

      insert_field(tree, "xim.error.detail_data", buffer(12, len))
   end
end

function dissect_XIM_QUERY_EXTENSION(buffer, pinfo, tree, endian)
   local subtree
   local length
   local p
   local i

   length = get_data(buffer, 2, 2)
   p = Pad(length)
   i = 0

   insert_field(tree, "xim.im",                         buffer(0, 2))
   insert_field(tree, "xim.query_extension.length",     buffer(2, 2))
   subtree = insert_field(tree, "xim.query_extension.extensions", buffer(4, length))
   while i < length do
      local str_len = buffer(4 + i, 1):uint()
      insert_raw(subtree, buffer(4 + i + 1, str_len), buffer(4 + i + 1, str_len):string())
      i = i + str_len + 1
   end
   insert_raw(tree, buffer(4 + length, p), "padding")
end

function dissect_EXT(buffer, tree)
   local ext
   local n
   local p

   n = get_data(buffer, 2, 2)
   p = Pad(n)

   ext = tree:add(xim, buffer(0, 4 + n + p), "EXT")
   insert_raw(ext, buffer(0, 1), "major-opcode: " .. get_data(buffer, 0, 1))
   insert_raw(ext, buffer(1, 1), "minor-opcode: " .. get_data(buffer, 1, 1))
   insert_raw(ext, buffer(2, 2), "length: "       .. get_data(buffer, 2, 2))
   insert_raw(ext, buffer(4, n), "name: "         .. buffer(4, n):string())
   if p > 0 then
      insert_raw(ext, buffer(4 + n, p), "padding")
   end

   return 4 + n + p
end

function dissect_XIM_QUERY_EXTENSION_REPLY(buffer, pinfo, tree, endian)
   local subtree
   local length
   local i

   length = get_data(buffer, 2, 2)
   i = 0

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.query_extension_reply.length", buffer(2, 2))
   if length > 0 then
      subtree = insert_field(tree, "xim.query_extension_reply.extensions", buffer(4, length))
      while i < length do
	 i = i + dissect_EXT(buffer(4 + i, length - i), subtree)
      end
   end
end

function dissect_STR(buffer, tree)
   local length
   local subtree

   length = buffer(0, 1):uint()
   if length > 0 then
      subtree = insert_raw(tree, buffer(0, length), "STR")
      insert_raw(subtree, buffer(0, 1),      "length: " .. length)
      insert_raw(subtree, buffer(1, length), "data: " .. buffer(1, length):string())
   end

   return length + 1
end

function dissect_ENCODINGINFO(buffer, tree)
   local subtree
   local n
   local p

   n = get_data(buffer, 0, 2)
   p = Pad(2 + n)

   subtree = insert_raw(tree, buffer(), "ENCODINGINFO")
   insert_raw(tree, buffer(0, 2), "length")
   if n > 0 then
      insert_raw(tree, buffer(2, n), "info: " .. buffer(2, n):string())
   end
   if p > 0 then
      insert_raw(tree, buffer(2 + n, p), "padding")
   end

   return 2 + p + n
end

function dissect_XIM_ENCODING_NEGOTIATION(buffer, pinfo, tree, endian)
   local subtree
   local n
   local m
   local p
   local i

   n = get_data(buffer, 2, 2)
   p = Pad(n)
   m = get_data(buffer, 4 + n + p, 2)
   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.encoding_negotiation.named_length", buffer(2, 2))
   if n > 0 then
      subtree = insert_field(tree, "xim.encoding_negotiation.named", buffer(4, n))
      i = 0
      while i < n do
	 i = i + dissect_STR(buffer(4 + i, n - i), subtree)
      end
   end

   if p > 0 then
      insert_raw(tree, buffer(4 + n, p), "padding")
   end
   insert_field(tree, "xim.encoding_negotiation.detail_length", buffer(4 + n + p, 2))
   insert_raw(tree, buffer(4 + n + p + 2, 2), "unused")
   if m > 0 then
      subtree = insert_field(tree, "xim.encoding_negotiation.detail", buffer(4 + n + p + 2, m))
      i = 0
      while i < m do
	 i = i + dissect_ENCODINGINFO(buffer(4 + n + p + 2 + i, m - i), subtree)
      end
   end
end

function dissect_XIM_ENCODING_NEGOTIATION_REPLY(buffer, pinfo, tree, endian)
   local category
   local categories = {
      [0] = "name",
      [1] = "detailed data"
   }

   category = get_data(buffer, 2, 2)

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.encoding_negotiation_reply.category", buffer(2, 2), categories[category])
   insert_field(tree, "xim.encoding_negotiation_reply.encoding", buffer(4, 2))
   insert_raw(tree, buffer(6, 2), "unused")
end

function dissect_XIM_GET_IM_VALUES(buffer, pinfo, tree, endian)
   local n
   local p

   n = get_data(buffer, 2, 2)
   p = Pad(n)

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.get_im_values.length", buffer(2, 2))

   if n > 0 then
      local subtree
      local i

      subtree = insert_field(tree, "xim.get_im_values.ids", buffer(4, n))
      i = 0

      while i < n do
	 local desc
	 local id
	 local name

	 id = get_data(buffer, 4 + i, 2)
	 desc = "id: " .. id
	 name = get_attribute_name("XIM", id)
	 if name ~= nil then
	    desc = desc .. " (" .. name .. ")"
	 end

	 insert_raw(subtree, buffer(4 + i, 2), desc)
	 i = i + 2
      end
   end

   if p > 0 then
      insert_raw(tree, buffer(4 + n, p), "padding")
   end
end

function dissect_XIM_GET_IC_VALUES(buffer, pinfo, tree, endian)
   local subtree
   local n
   local i
   local ids
   local sep
   local max

   ids = ""
   sep = ""
   max = buffer:len() - 6
   n = get_data(buffer, 4, 2)
   i = 0

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.ic", buffer(2, 2))
   insert_field(tree, "xim.get_ic_values.length", buffer(4, 2))
   if n > 0 then
      subtree = insert_field(tree, "xim.get_ic_values.list", buffer(6, n))
      i = 0

      while i < n do
	 local id
	 local desc
	 local name

	 id = get_data(buffer, 6 + i, 2)
	 desc = "id: " .. id
	 name = get_attribute_name("XIC", id)
	 if name ~= nil then
	    desc = desc .. " (" .. name .. ")"
	 end

	 insert_raw(subtree, buffer(6 + i, 2), desc)
	 i = i + 2
      end
   end
end

function get_forward_flag_names(flags)
   local result = ""
   local sep = ""
   local flag_names = {
      [1] = "synchronous",
      [2] = "request filtering",
      [4] = "request lookupstring"
   }
   local name
   local flag

   for flag, name in pairs(flag_names) do
      if bit32.band(flags, flag) ~= 0 then
	 result = result .. sep .. flag_names[flag]
	 sep = " | "
      end
   end

   return result
end

function dissect_XIM_FORWARD_EVENT(buffer, pinfo, tree, endian)
   local subtree
   local length
   local flag_desc

   flag_desc = get_forward_flag_names(get_data(buffer, 4, 2))

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.ic", buffer(2, 2))
   insert_field(tree, "xim.forward_event.flag", buffer(4, 2), flag_desc)
   insert_field(tree, "xim.forward_event.serial", buffer(6, 2))

   if buffer:len() > 8 then
      subtree = insert_raw(tree, buffer(8, -1), "XCoreKeyEvent data")
      dissect_XCoreKeyEvent(buffer(8, -1), pinfo, subtree, endian)
   end
end

function dissect_XCoreKeyEvent(buffer, pinfo, tree, endian)
   insert_raw(tree, buffer( 0, 1), "type: "        .. get_data(buffer,  0, 1))
   insert_raw(tree, buffer( 1, 1), "detail: "      .. get_data(buffer,  1, 1))
   insert_raw(tree, buffer( 2, 2), "sequence: "    .. get_data(buffer,  2, 2))
   insert_raw(tree, buffer( 4, 4), "time: "        .. get_data(buffer,  4, 4))
   insert_raw(tree, buffer( 8, 4), "root: "        .. get_data(buffer,  8, 4))
   insert_raw(tree, buffer(12, 4), "window: "      .. get_data(buffer, 12, 4))
   insert_raw(tree, buffer(16, 4), "child: "       .. get_data(buffer, 16, 4))
   insert_raw(tree, buffer(20, 2), "root-x: "      .. get_data(buffer, 20, 2))
   insert_raw(tree, buffer(22, 2), "root-y: "      .. get_data(buffer, 22, 2))
   insert_raw(tree, buffer(24, 2), "event-x: "     .. get_data(buffer, 24, 2))
   insert_raw(tree, buffer(26, 2), "event-y: "     .. get_data(buffer, 26, 2))
   insert_raw(tree, buffer(28, 2), "state: "       .. get_data(buffer, 28, 2))
   insert_raw(tree, buffer(30, 1), "same-screen: " .. get_data(buffer, 30, 1))
   insert_raw(tree, buffer(31, 1), "unused: "      .. get_data(buffer, 31, 1))
end

function dissect_XIM_imic(buffer, pinfo, tree, endian, opcode_name)
   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.ic", buffer(2, 2))
end

function dissect_XIM_im(buffer, pinfo, tree, endian, opcode_name)
   insert_field(tree, "xim.im", buffer(0, 2))
end

function get_commit_flag_names(flags)
   local result = ""
   local sep = ""
   local names = {
      [1] = "synchronous",
      [2] = "XLookupChars",
      [4] = "XLookupKeySym"
   }
   local flag
   local name

   for flag, name in pairs(names) do
      if bit32.band(flags, flag) ~= 0 then
	 result = result .. sep .. names[flag]
	 sep = " | "
      end
   end

   return result
end

function dissect_ATTRIBUTE(buffer, tree, attr_type)
   local subtree
   local n
   local p
   local id
   local attr_label
   local attr_name

   n = get_data(buffer, 2, 2)
   p = Pad(n)
   id = get_data(buffer, 0, 2)
   attr_label = "attribute-ID: " .. id
   attr_name = get_attribute_name(attr_type, id)

   if attr_name ~= nil then
      attr_label = attr_label .. " (" .. get_attribute_name(attr_type, id) .. ")"
   end

   subtree = insert_raw(tree, buffer(0, 4 + n + p), attr_type .. "ATTRIBUTE")
   insert_raw(subtree, buffer(0, 2), attr_label)
   insert_raw(subtree, buffer(2, 2), "length: " .. n)
   if n > 0 then
      insert_raw(subtree, buffer(4, n), "value: 0x" .. buffer(4, n))
   end
   if p > 0 then
      insert_raw(subtree, buffer(4 + n, p), "padding")
   end

   return 4 + n + p
end

function dissect_XIM_CREATE_IC(buffer, pinfo, tree, endian, opcode_name)
   local subtree
   local n
   local i

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.create_ic.attrs_length", buffer(2, 2))

   i = 0
   n = get_data(buffer, 2, 2)

   subtree = insert_field(tree, "xim.create_ic.attrs", buffer(4, n))

   while i < n do
      i = i + dissect_ATTRIBUTE(buffer(4 + i, n - i), subtree, "XIC")
   end
end

function dissect_XIM_COMMIT(buffer, pinfo, tree, endian, opcode_name)
   local flag
   local flag_desc
   local offset
   local p

   flag = get_data(buffer, 4, 2)
   flag_desc = get_commit_flag_names(flag)
   offset = 6

   insert_field(tree, "xim.im", buffer(0, 2))
   insert_field(tree, "xim.ic", buffer(2, 2))
   insert_field(tree, "xim.commit.flag", buffer(4, 2), flag_desc)

   if bit32.band(flag, 4) ~= 0 then -- XLookupKeySym
      insert_field(tree, "xim.commit.unused", buffer(6, 2))
      insert_field(tree, "xim.commit.keysym", buffer(8, 4))
      offset = offset + 6
   end

   if bit32.band(flag, 2) ~= 0 then -- XLookupChars
      insert_field(tree, "xim.commit.string_length", buffer(offset, 2))
      len = get_data(buffer, offset, 2)
      if len > buffer:len() - offset - 2 then
	 insert_field(tree, "xim.commit.string_data", buffer(offset + 2, -1))
      else
	 insert_field(tree, "xim.commit.string_data", buffer(offset + 2, len))
      end

      p = Pad(len)
      if p > 0 then
	 insert_raw(tree, buffer(offset + 2 + len, p), "padding")
      end
   end
end

function get_data(buffer, start, len)
   local stream
   local endian

   stream = assert(tonumber(tostring(tcp_stream())))
   endian = endians[stream]

   if endian == "B" then
      return buffer(start, len):uint()
   end

   return buffer(start, len):le_uint()
end

xim_dissectors = {
   ["XIM_CONNECT"]                    = dissect_XIM_CONNECT,
   ["XIM_CONNECT_REPLY"]              = dissect_XIM_CONNECT_REPLY,
   ["XIM_DISCONNECT"]                 = dissect_XIM_DISCONNECT,
   ["XIM_DISCONNECT_REPLY"]           = dissect_XIM_DISONNECT_REPLY,

   ["XIM_AUTH_REQUIRED"]              = dissect_XIM_AUTH_REQUIRED,
   ["XIM_AUTH_REPLY"]                 = dissect_XIM_AUTH_REPLY,
   ["XIM_AUTH_NEXT"]                  = dissect_XIM_AUTH_NEXT,
   ["XIM_AUTH_SETUP"]                 = dissect_XIM_AUTH_SETUP,
   ["XIM_AUTH_NG"]                    = dissect_XIM_AUTH_NG,

   ["XIM_ERROR"]                      = dissect_XIM_ERROR,

   ["XIM_OPEN"]                       = dissect_XIM_OPEN,
   ["XIM_OPEN_REPLY"]                 = dissect_XIM_OPEN_REPLY,
   ["XIM_CLOSE"]                      = dissect_XIM_im,
   ["XIM_CLOSE_REPLY"]                = dissect_XIM_im,
   ["XIM_REGISTER_TRIGGERKEYS"]       = dissect_XIM_REGISTER_TRIGGERKEYS,
   ["XIM_TRIGGER_NOTIFY"]             = dissect_XIM_TRIGGER_NOTIFY,
   ["XIM_TRIGGER_NOTIFY_REPLY"]       = dissect_XIM_imic,
   ["XIM_SET_EVENT_MASK"]             = dissect_XIM_SET_EVENT_MASK,
   ["XIM_ENCODING_NEGOTIATION"]       = dissect_XIM_ENCODING_NEGOTIATION,
   ["XIM_ENCODING_NEGOTIATION_REPLY"] = dissect_XIM_ENCODING_NEGOTIATION_REPLY,
   ["XIM_QUERY_EXTENSION"]            = dissect_XIM_QUERY_EXTENSION,
   ["XIM_QUERY_EXTENSION_REPLY"]      = dissect_XIM_QUERY_EXTENSION_REPLY,
   ["XIM_SET_IM_VALUES"]              = dissect_XIM_SET_IM_VALUES,
   ["XIM_SET_IM_VALUES_REPLY"]        = dissect_XIM_im,
   ["XIM_GET_IM_VALUES"]              = dissect_XIM_GET_IM_VALUES,
   ["XIM_GET_IM_VALUES_REPLY"]        = dissect_XIM_GET_IM_VALUES_REPLY,

   ["XIM_CREATE_IC"]                  = dissect_XIM_CREATE_IC,
   ["XIM_CREATE_IC_REPLY"]            = dissect_XIM_imic,
   ["XIM_DESTROY_IC"]                 = dissect_XIM_imic,
   ["XIM_DESTROY_IC_REPLY"]           = dissect_XIM_imic,
   ["XIM_SET_IC_VALUES"]              = dissect_XIM_SET_IC_VALUES,
   ["XIM_SET_IC_VALUES_REPLY"]        = dissect_XIM_imic,
   ["XIM_GET_IC_VALUES"]              = dissect_XIM_GET_IC_VALUES,
   ["XIM_GET_IC_VALUES_REPLY"]        = dissect_XIM_GET_IC_VALUES_REPLY,
   ["XIM_SET_IC_FOCUS"]               = dissect_XIM_imic,
   ["XIM_UNSET_IC_FOCUS"]             = dissect_XIM_imic,
   ["XIM_FORWARD_EVENT"]              = dissect_XIM_FORWARD_EVENT,
   ["XIM_SYNC"]                       = dissect_XIM_imic,
   ["XIM_SYNC_REPLY"]                 = dissect_XIM_imic,
   ["XIM_COMMIT"]                     = dissect_XIM_COMMIT,
   ["XIM_RESET_IC"]                   = dissect_XIM_imic,
   ["XIM_RESET_IC_REPLY"]             = dissect_XIM_RESET_IC_REPLY,

   ["XIM_GEOMETRY"]                   = dissect_XIM_imic,
   ["XIM_STR_CONVERSION"]             = dissect_XIM_STR_CONVERSION,
   ["XIM_STR_CONVERSION_REPLY"]       = dissect_XIM_STR_CONVERSION_REPLY,
   ["XIM_PREEDIT_START"]              = dissect_XIM_imic,
   ["XIM_PREEDIT_START_REPLY"]        = dissect_XIM_PREEDIT_START_REPLY,
   ["XIM_PREEDIT_DRAW"]               = dissect_XIM_PREEDIT_DRAW,
   ["XIM_PREEDIT_CARET"]              = dissect_XIM_PREEDIT_CARET,
   ["XIM_PREEDIT_CARET_REPLY"]        = dissect_XIM_PREEDIT_CARET_REPLY,
   ["XIM_PREEDIT_DONE"]               = dissect_XIM_imic,
   ["XIM_STATUS_START"]               = dissect_XIM_imic,
   ["XIM_STATUS_DRAW"]                = dissect_XIM_STATUS_DRAW,
   ["XIM_STATUS_DONE"]                = dissect_XIM_imic,
   ["XIM_PREEDITSTATE"]               = dissect_XIM_PREEDITSTATE
}

function xim.dissector(buffer, pinfo, tree)
   local opcode_major
   local opcode_minor
   local opcode_name
   local stream
   local endian
   local length
   local header_subtree
   local payload_subtree

   pinfo.cols.protocol = "XIM"

   opcode_major = buffer(0, 1):uint()
   opcode_minor = buffer(1, 1):uint()
   opcode_name = xim_opcodes[opcode_major]

   stream = assert(tonumber(tostring(tcp_stream())))

   if opcode_name == "XIM_CONNECT" then
      endian = buffer(4, 1):string()
      endians[stream] = endian
   else
      endian = endians[stream]
   end

   length = get_data(buffer, 2, 2)

   subtree = tree:add(xim, buffer())
   header_subtree = subtree:add(xim, buffer(0, 4), "Header")
   insert_field(header_subtree, "xim.major_opcode", buffer(0, 1))
   insert_field(header_subtree, "xim.minor_opcode", buffer(1, 1))
   insert_field(header_subtree, "xim.length",       buffer(2, 2), length * 4 .. " bytes")

   if xim_dissectors[opcode_name] ~= nil then
      payload_subtree = subtree:add(xim, buffer(4, -1), opcode_name .. " data")
      xim_dissectors[opcode_name](buffer(4, -1), pinfo, payload_subtree, endian, opcode_name)
   else
      subtree:add(xim, buffer(4, -1), "Payload")
   end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1234, xim)
