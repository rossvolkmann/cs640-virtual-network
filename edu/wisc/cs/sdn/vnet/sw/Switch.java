package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.io.Console;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	// Note: a real switch has a MAC address, but for the purposes of this assignment
	// the switch MAC adddress is not relevant.  

	/**
	 * switchTable is a ConcurrentHashMap that uses the string representation
	 * of a MacAddress as its key.  
	 * 
	 * The value contains the interface associated with that MacAddress as well
	 * as the time that table entry was last refreshed.
	 */
	private ConcurrentHashMap<String, SwitchTableRow> switchTable;
	private ExpirationChecker rowChecker;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		switchTable = new ConcurrentHashMap<String, SwitchTableRow>();
		rowChecker = new ExpirationChecker(switchTable);
		rowChecker.start();
	}

	// Creates a thread that checks the table for expired rows once per second.
	private class ExpirationChecker extends Thread{

		private ConcurrentHashMap<String, SwitchTableRow> switchTableReference;
		public ExpirationChecker(ConcurrentHashMap<String, SwitchTableRow> reference){
			this.switchTableReference = reference;
		}

		public void run(){
			while(true){
				try{
					Thread.sleep(1000);
					// Logic
					for(String ifaceKey : this.switchTableReference.keySet()){
						if(System.currentTimeMillis() - switchTableReference.get(ifaceKey).getTTL() > 15000){
							switchTableReference.remove(ifaceKey);
							//System.out.println("DEBUG: MacAddress " +ifaceKey+ " timed out of switchtable.");
						}
					}
				} catch(Exception e){
					System.out.println(e.getMessage());
				}
			}// while
		}// run()
	}// ExpirationChecker class

	/**
	 * SwitchTableRow is a POJO that represents a row of the SwitchTable
	 * 
	 * It contains the following "columns" MAC Address / TTL
	 */
	private class SwitchTableRow {
		private Iface interfaceName;
		private long TTL;

		private SwitchTableRow(Iface interfaceName, long TTL){
			this.interfaceName = interfaceName;
			this.TTL = TTL;
		}

		//Getters
		private Iface getInterfaceName(){return this.interfaceName;}
		private long getTTL(){return this.TTL;}

		//Setter
		private void setTTL(long TTL){this.TTL = TTL;}

		@Override
		public String toString(){
			return "DEBUG: macAddress: " +this.interfaceName+ " TTL: " +this.TTL;
		}

	}// SwitchTableRow class

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		String sourceMacAddr = Arrays.toString(etherPacket.getSourceMACAddress());
		String destMacAddr = Arrays.toString(etherPacket.getDestinationMACAddress());

		//check if packet source is in table
			if(!switchTable.containsKey(sourceMacAddr)){
				// if MacAddress is not in table, add it
				switchTable.put(sourceMacAddr, new SwitchTableRow(inIface, System.currentTimeMillis()));
				//System.out.println("DEBUG: Source " +sourceMacAddr+ " added to table with interface " +inIface.getName());
			}else{
				// if source MacAddress is in table, refresh TTL
				switchTable.get(sourceMacAddr).setTTL(System.currentTimeMillis());
			}

		//check if packet dest is in table
			if(switchTable.containsKey(destMacAddr)){
				// if match found, send the packet
				this.sendPacket(etherPacket, switchTable.get(destMacAddr).getInterfaceName());
				//System.out.println("DEBUG: Sending packet from " +sourceMacAddr+ " to " +destMacAddr);
			}
			else {
				// if no match is found, flood all interfaces except the source
				//System.out.println("DEBUG: No dest match found, Flooding");
				for(String ifaceKey : this.interfaces.keySet()){
					if(ifaceKey.equals(inIface.getName())){
						// if key matches 
						continue;
					}else{
						this.sendPacket(etherPacket, this.interfaces.get(ifaceKey));
						//System.out.println("DEBUG: Sending packet from " +sourceMacAddr+ " to interface: " +ifaceKey);
					}
				}
			}
	}
}
