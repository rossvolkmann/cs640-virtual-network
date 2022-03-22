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
			sendTimeExceededICMP(etherPacket, inIface);
			return;
		}
		//resetChecksum to avoid checksum issues at next router
		packet.resetChecksum();

		// if you've gotten this far you've got a valid packet

		// Lookup the correct destination in the routeTable
		RouteEntry match = routeTable.lookup(packet.getDestinationAddress()); //note - match can be null
		if(match == null){
			//System.out.println("DEBUG: no match found in routeTable, dropping packet from " +this.getHost());
			return; // no default routes in static rout tables, so drop packet
		}

		// Use routeTable lookup results to get the sourceInterface
		//Iface targetInterface = match.getInterface(); // get the interface from the route table
		String sourceInterfaceName = match.getInterface().getName();
		Iface sourceInterface = this.interfaces.get(sourceInterfaceName);
		if(sourceInterface.equals(inIface)){
			//System.out.println("DEBUG: outbound source interface is equal to incoming packet interface.  Dropping packet from " +this.getHost());
			return;
		}
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
		MACAddress destinationMAC = this.arpCache.lookup(nextHop).getMac();
		//System.out.println("DEBUG: Lookup arp entry: " +this.arpCache.lookup(nextHop));
		//System.out.println("DEBUG: Destination MAC address: " +destinationMAC);
		if (destinationMAC == null){
			//System.out.println("DEBUG: no match found in ARP table, dropping packet from " +this.getHost());
			return; //drop packet
		}
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

	private void sendTimeExceededICMP(Ethernet etherPacket, Iface inIface){
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
		int sourceIPAddress = inIface.getIpAddress(); // set new source as IP address of this router's receiving interface
		ip.setSourceAddress(sourceIPAddress);
		int destinationIPAddress = originalIPPacket.getSourceAddress(); // set new destination as original source
		ip.setDestinationAddress(destinationIPAddress);

		// populate the ICMP header
		byte icmpType11 = (byte)11;
		icmp.setIcmpType(icmpType11);
		byte icmpCode0 = (byte)0;
		icmp.setIcmpCode(icmpCode0);

		// populate payload
		byte[] icmpPayload = new byte[4 + (int)originalIPPacket.getHeaderLength() + 8];
		ByteBuffer bb = ByteBuffer.wrap(icmpPayload);
		byte[] padding = {0,0,0,0};
		bb.put(padding);
		bb.put(originalIPPacket.serialize(),0,((int)originalIPPacket.getHeaderLength() + 8));

		// send the ICMP packet out
		System.out.println("DEBUG: Sending ICMP time exceeded packet");
		this.sendPacket(ether, inIface);
		
	} // sendTimeExceededICMP
}
