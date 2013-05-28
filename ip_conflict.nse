#!/usr/bin/lua
local nmap = require "nmap"
local stdnse = require "stdnse"
local bin = require "bin"
local ipOps = require "ipOps"
local packet = require "packet"

description = [[
Detect if the target have ip conflict, by broadcasting an ARP 
request, and check the LAN responses. If there are more than one
ARP reply packet received, the target should have an ip conflict.
]]

--@args target Host arp request sent, if not 
--specified, 127.0.0.1 will set. 
--
--@usage
--nmap --script ip_conflict 
--nmap --script ip_conflict --script-args "target=192.168.1.3"
--
--@output
--Pre-scan script results:
--| ip_conflict: 
--|	  219.246.66.234
--|_	78:ac:c0:55:45:4a
--|_	00:0a:e4:34:d6:32

author = "WEN Pingbo"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default","safe","discovery"}

prerule = function()
  if nmap.address_family() ~= 'inet' then
	stdnse.print_verbose("%s is IPv4 only.", SCRIPT_NAME)
	return false
  end
  if not nmap.is_privileged() then
	stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
	return false
  end
  return true
end

--get active interface related to target, by sending an udp 
--packet, and traverse the whole interface in localhost, pick the 
--active one
local getInterface = function(target)
  local sock = nmap.new_socket()
  local status,err = sock:connect(target,"8888","udp")
  if(not status) then
	stdnse.print_verbose("%s:%s",SCRIPT_NAME,err)
	return
  end
  local status,address = sock:get_info()
  if(status) then
	for _,v in pairs(nmap.list_interfaces()) do
	  if(v.address == address) then
		return v
	  end
	end
  end
end

--convert the six-byte mac address to a string, like
--00:0a:e4:34:d6:32
local mac_to_str = function(mac)
  local result=string.format("%02x",packet.u8(mac,0))
  for i = 1,5 do
	result = result .. string.format(":%02x",packet.u8(mac,i))
  end
  return result
end

--arp reply packet listener
local arpListener = function(interface,target,timeout,responses)
  local start = nmap.clock_ms()
  local co = nmap.condvar(responses)
  local pcap = nmap.new_socket()
  local filter="arp"
  pcap:pcap_open(interface.device,64,false,filter)
  pcap:set_timeout(10)
  local test = bin.pack("B",ipOps.ip_to_bin(target))
  local count = 1
  while(nmap.clock_ms()-start < timeout) do
	local status, length, layer2, layer3 = pcap:pcap_receive()
	if(
	  status and 
	  test == string.sub(layer3,15,18) and --compare with src ip and target
	  string.char(0x00,0x02) == string.sub(layer3,7,8) --check the arp reply type
	  ) then
	  responses[count] = mac_to_str(string.sub(layer2,7,12))
	  count = count + 1
	end
  end
  pcap:pcap_close()
  co "signal"
end

local arpRequestPacketBuild = function(iface,target)
  local frame = string.char(0xff,0xff,0xff,0xff,0xff,0xff) ..
				iface.mac ..
				string.char(0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01) ..
				iface.mac ..
				bin.pack("B",ipOps.ip_to_bin(iface.address)) ..
				string.char(0x00,0x00,0x00,0x00,0x00,0x00) ..
				bin.pack("B",ipOps.ip_to_bin(target))
  return frame
end

local arpSender = function(iface,target)
  local frame=arpRequestPacketBuild(iface,target)
  local dnet=nmap.new_dnet()
  if(not dnet) then
	stdnse.print_verbose("%s:%s",SCRIPT_NAME,"get dnet object error")
	return
  end
  dnet:ethernet_open(iface.device)
  dnet:ethernet_send(frame)
  dnet:ethernet_close()
end

action = function()
  local target = stdnse.get_script_args(SCRIPT_NAME .. ".target") or "127.0.0.1"
  local interface=nmap.get_interface()
  local responses={}
  if(interface) then
	interface = nmap.get_interface_info(interface)
  else
	interface = getInterface(target)
  end
  if(not interface) then
	stdnse.print_verbose("%s:%s",SCRIPT_NAME,"get iface error")
	return
  end
  local co = nmap.condvar(responses)
  stdnse.new_thread(arpListener,interface,target,100,responses)
--wait for the listener thread 
  stdnse.sleep(0.1)
  arpSender(interface,target)
  co "wait"

  local out = ""
  if(#responses > 0) then
	out = out .. "\n\t" .. target
	for i = 1,#responses do
	  out = out .. "\n\t\t" .. responses[i]
	end
	return out
  end
end

