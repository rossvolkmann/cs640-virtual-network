package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		// if NOT IPv4 packet, drop packet
		if(etherPacket.getEtherType() != Ethernet.TYPE_IPv4){ // refactor this later
			//System.out.println("DEBUG: incoming packet was not type IPv4.\n"
			//+"Was type " +etherPacket.getEtherType()+ "  Dropping from " +this.getHost());
			return;
		}
		// confirm the checksum and drop if invalid
		IPv4 packet = (IPv4)etherPacket.getPayload();
		// verify the checksum and drop packet if not equal
		int packetChecksum = packet.getChecksum();
		packet.resetChecksum();
		packet.serialize();
		if(packetChecksum != packet.getChecksum()){
			//System.out.println("DEBUG: packet dropped due to bad checksum at " +this.getHost());
			return; // drop packet
		}
		// verify the TTL, decrement TTL and drop if TTL expired
		byte TTL = packet.getTtl();
		packet.setTtl((byte)(TTL - 1));
		if(TTL <= 1){ // drop packet
			System.out.println("DEBUG: packet will be dropped due to expired TTL at " +this.getHost());
			System.out.println("DEBUG: Sending ICMP packet for Time Exceeded...");
			sendICMPPacket(etherPacket, inIface, 11, 0);
			return;
		}
		//resetChecksum to avoid checksum issues at next router
		packet.resetChecksum();

		// Valid packets past this point

		// Lookup the correct destination in the routeTable
		RouteEntry match = routeTable.lookup(packet.getDestinationAddress()); //note - match can be null
		if(match == null){
			System.out.println("DEBUG: no match found in routeTable, dropping packet from " +this.getHost());
			sendICMPPacket(etherPacket, inIface, 3, 0);
			return; // no default routes in static rout tables, so drop packet
		}

		// Check if packet is destined for one of the router's interfaces
		// Taken from the assign2 
		for (Iface iface: this.interfaces.values()){
			if(packet.getDestinationAddress() == iface.getIpAddress()){
				if(packet.getProtocol() == IPv4.PROTOCOL_TCP) { //IP packet contains TCP/UDP message
					sendICMPPacket(etherPacket, inIface, 3 , 3); // send destination port unreachable
					return;
				} else if(packet.getProtocol() == IPv4.PROTOCOL_ICMP) { //IP packet contains ICMP message
					//Check if ICMP message is an Echo Request
					ICMP icmp = (ICMP)packet.getPayload();
					byte icmpType8 = (byte)8;
					if(icmp.getIcmpType() == icmpType8){
						// send Echo Reply
						sendICMPPacket(etherPacket, inIface, 0, 0);
					}
					return;
				}
				return;
			}
		}

		// Use routeTable lookup results to get the sourceInterface 
		// This was my original interpretation of the above.  Is this right?
		//System.out.println("DEBUG: targetInterface is " +sourceInterface);

		//Check if destination is directly connected to Router or if nextHop should be to another gateway.  
		int gateway = match.getGatewayAddress();
		int nextHop;
		if(gateway == 0){ // if gateway is 0 send it home
			nextHop = packet.getDestinationAddress();
		}else{ // send packet to next gateway
			nextHop = gateway;
		}
		//System.out.println("DEBUG: gateWay is " +gateway);
		//System.out.println("DEBUG: Nexthop is " +nextHop);
		
		//Lookup the destination MAC Address for nextHop in the ARP Table
		//System.out.println("DEBUG: Lookup arp entry: " +this.arpCache.lookup(nextHop));
		//System.out.println("DEBUG: Destination MAC address: " +destinationMAC);
		ArpEntry destinationArp = this.arpCache.lookup(nextHop);
		if (destinationArp == null){
			System.out.println("DEBUG: no match found in ARP table, dropping packet from " +this.getHost());
			sendICMPPacket(etherPacket, inIface, 3, 1);
			return; //drop packet
		}
		MACAddress destinationMAC = destinationArp.getMac(); // throwing NPE here when given bogus MAC address
		byte[] destinationMACAddress = destinationMAC.toBytes();
		//System.out.println("DEBUG: Destination MAC address to bytes: " +destinationMACAddress);

		// Extract the sourceMAC from the source interface identified above
		MACAddress sourceMAC = sourceInterface.getMacAddress();
		//System.out.println("Source MAC " +sourceMAC);
		
		if(sourceMAC != null){ // in theory sourceMAC should never be null, but this check guards against POX issues found during testing
			byte[] sourceMACToBytes = sourceMAC.toBytes();
			//System.out.println("Source MACToBytes " +sourceMACToBytes);
			etherPacket.setSourceMACAddress(sourceMACToBytes); // edit the etherPacket's sourceMAC
		}
		
		etherPacket.setDestinationMACAddress(destinationMACAddress); // edit the etherPacket's destinationMAC
		this.sendPacket(etherPacket, sourceInterface); // forward the packet 
		//System.out.println("DEBUG: sending packet " +etherPacket+ " on interface " +sourceInterface);
	} // handlePacket

	/*
	 * Given an etherPacket, sends an ICMP packet out on the specified interface with a given type and code.
	 * 
	 * (Type, Code) Combinations
	 * (11,0) Time Exceeded
	 * (3,0) Destination Network Unreachable
	 * (3,1) Destination Host Unreachable
	 * (3,3) Destination Port Unreachable
	 * (0,0) Echo Reply (DO NOT USE)
	 * 
	 * Note: all types and codes should be entered as integer values. 
	 */
	private void sendICMPPacket(Ethernet etherPacket, Iface inIface, int icmpType, int icmpCode){
		// System.out.println("DEBUG: inIface is " +inIface.getName() + " " +inIface.getMacAddress()+ " " +inIface.getIpAddress());
		// create an ICMP packet and nest it inside of an IPv4 + Ethernet packet
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		IPv4 originalIPPacket = (IPv4)etherPacket.getPayload(); // original incoming IPv4 Packet

		// set the Ethernet destination as the MAC address of the nexthop on the way back to packet origin
		RouteEntry originMatch = routeTable.lookup(originalIPPacket.getSourceAddress());
		if(originMatch == null){
			return; // this should never happen, but let's be safe
		}
		String sourceInterfaceName = originMatch.getInterface().getName();
		Iface sourceInterface = this.interfaces.get(sourceInterfaceName);
		// System.out.println("DEBUG: sourceInterface is " +sourceInterface.getName() + " " +sourceInterface.getMacAddress()+ " " +sourceInterface.getIpAddress());

		// populate the Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		// set the Ethernet source as the interface packet was received on
		byte[] sourceMac = sourceInterface.getMacAddress().toBytes(); // this is throwing a NPE
		ether.setSourceMACAddress(sourceMac);
		//Check if destination is directly connected to Router or if nextHop should be to another gateway.  
		int gateway = originMatch.getGatewayAddress();
		int nextHop;
		if(gateway == 0){ // if gateway is 0 send it home
			nextHop = originalIPPacket.getSourceAddress();
		}else{ // send packet to next gateway
			nextHop = gateway;
		}
		MACAddress destinationMAC = this.arpCache.lookup(nextHop).getMac();
		byte[] destinationMacBytes = destinationMAC.toBytes(); // ??? what is the destination for this packet?
		ether.setDestinationMACAddress(destinationMacBytes);

		// populate the IP header
		byte ttl = (byte)64;
		ip.setTtl(ttl);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		int destinationIPAddress, sourceIPAddress;
		sourceIPAddress = sourceInterface.getIpAddress(); // set new source as IP address of this router's receiving interface
		destinationIPAddress = originalIPPacket.getSourceAddress(); // set new destination as original source
		ip.setSourceAddress(sourceIPAddress);
		ip.setDestinationAddress(destinationIPAddress);

		// populate the ICMP header
		icmp.setIcmpType((byte)icmpType);
		icmp.setIcmpCode((byte)icmpCode);

		// populate payload
		if(icmpType == 0 && icmpCode == 0){ // construct an Echo Reply packet
			ICMP echoPacket = (ICMP)originalIPPacket.getPayload();
			icmp.setPayload(echoPacket.getPayload());
			//data.setData(echoPacket.getPayload().serialize()); // this seems wrong???
		}else{ // construct a standard ICMP packet
			int numBytesInHeader = (int)originalIPPacket.getHeaderLength() * 4; // need to multiply by 4 to cast int32 to bytes
			byte[] icmpPayload = new byte[4 + numBytesInHeader + 8];
			ByteBuffer bb = ByteBuffer.wrap(icmpPayload);
			byte[] padding = {0,0,0,0};
			bb.put(padding);
			bb.put(originalIPPacket.serialize(),0,numBytesInHeader + 8);
			data.setData(icmpPayload); // this was missing with last issue
		}
		// send the ICMP packet out
		// System.out.println("DEBUG: Sending ICMP time exceeded packet");
		this.sendPacket(ether, sourceInterface);
	}


}
