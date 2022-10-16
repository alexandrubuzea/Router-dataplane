/** Copyright 2022 Buzea Alexandru-Mihai-Iulian
 * E-mail: alexandru.buzea2007@stud.acs.upb.ro 
 */

#include "queue.h"
#include "skel.h"

/**
 * A function that performs the longest prefix match algorithm algorithm on a
 * sorted static routing table. The routing table must be sorted after 
 */
struct route_table_entry *lpm(struct route_table_entry *rtable, int route_entries, uint32_t daddr)
{
	// prepare binary search
	int start = 0, stop = route_entries - 1;

	// keep a pointer to the best entry found, NULL otherwise (if we haven't
	// found a suitable entry for the given next-hop's IP address)
	struct route_table_entry *best_entry = NULL;

	while (start <= stop) {
		int middle = start + ((stop - start) >> 1);
		struct route_table_entry *entry = rtable + middle;

		// classical binary search algorithm
		if (ntohl(entry->prefix & entry->mask) < ntohl(daddr & entry->mask)) {
			start = middle + 1;
		} else if (ntohl(entry->prefix & entry->mask) > ntohl(daddr & entry->mask)) {
			stop = middle - 1;
		} else {
			// if we found an entry, we keep it and look out for an
			// even better entry
			best_entry = rtable + middle;
			start = middle + 1;
		}
	}

	return best_entry;
}

/**
 * A function that performs linear search (only 10 entries) in the ARP
 * table of the router
 */ 
struct arp_entry *get_arp_entry(struct arp_entry *arp_table, int arp_entries, uint32_t daddr)
{
	for (int i = 0; i < arp_entries; ++i)
		if (arp_table[i].ip == daddr)
			return arp_table + i;
	
	return NULL;
}

/**
 * A function that performs deep copy to the package using dynamic
 * memory allocation (in order to put it in the queue - only IPv4 packages)
 */
packet *my_packet_strdup(packet *m)
{
	packet *to_ret = (packet *)malloc(sizeof(packet));
	DIE(!to_ret, "Packet malloc failed\n");

	memcpy(to_ret, m, sizeof(*m));

	return to_ret;
}

/**
 * A comparator function that sorts the entries in the routing table not after
 * the prefix field, but after prefix & mask field (the actual network address
 * of the next hop - the prefix field represents just a random IPv4 address from
 * the subnet he is a part of)
 */
int comparator(const void *f1, const void *f2)
{
	struct route_table_entry *first = (struct route_table_entry *)f1;
	struct route_table_entry *second = (struct route_table_entry *)f2;

	// check the difference between prefix & mask
	int diff = ntohl(first->prefix & first->mask) - ntohl(second->prefix & second->mask);

	// if the TRUE prefixes are different, return a corresponding result for qsort
	if (diff != 0)
		return (diff > 0 ? 1 : -1);

	// return the difference of the masks otherwise (ascending order after prefix
	// and mask in the same time)
	return ntohl(first->mask) - ntohl(second->mask);
}

int main(int argc, char *argv[])
{
	// the packet instance in which we will receive the info at a given step
	packet m;

	// a flag for the number of bytes we have received
	int rc;

	// the initial number of entries and capacity of the dynamic ARP table
	int arp_entries = 0;
	int arp_capacity = 10;

	// the dynamic allocation of memory for the ARP table
	struct arp_entry *arp_table = malloc(arp_capacity * sizeof(struct arp_entry));
	DIE(!arp_table, "malloc failed");

	// the dynamic allocation of memory for the routing table
	int route_entries = 100000;
	struct route_table_entry *rtable = malloc(route_entries * sizeof(struct route_table_entry));
	DIE(!rtable, "malloc failed");

	// parsing the routing table
	route_entries = read_rtable(argv[1], rtable);

	// sort the routing table according to the given criteria
	qsort(rtable, route_entries, sizeof(struct route_table_entry), comparator);

	// instantiating a queue for the packages for which we do not have an
	// ARP entry in the ARP table
	queue q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// extracting the ethernet header - L2 header
		struct ether_header * eth_hdr = (struct ether_header *)m.payload;
		
		// initializing a MAC address for filling in what we need
		uint8_t mac[ETH_ALEN] = {0};

		get_interface_mac(m.interface, mac);

		// if the MAC address does not match the interface address or the
		// broadcast MAC, then the package is dropped
		if (memcmp(eth_hdr->ether_dhost, mac, ETH_ALEN) != 0) {
			memset(mac, 0xff, ETH_ALEN);
			if (memcmp(eth_hdr->ether_dhost, mac, ETH_ALEN) != 0)
				continue; // drop package
		}

		// Part 1: if we have an IPv4 package
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			// extracting the IPv4 header
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// the information stored in the package - it will be used if the
			// package is of ICMP type.
			void *info = (void *)(((char *)ip_hdr) + sizeof(struct iphdr));

			// the old checksum + the calculation of the actual checksum, check
			// if the packet is corrupted
			uint16_t checksum = ip_hdr->check;
			ip_hdr->check = 0;

			int actual_checksum = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));

			// if the checksum in the check field differ from the actual checksum,
			// drop the packet
			if (checksum != actual_checksum)
				continue; // drop packet = wrong checksum = corrupted packet

			// if TTL field (time to live) has expired, drop the package and
			// send an ICMP error message (time exceeded).
			if (ip_hdr->ttl <= 1) {
				get_interface_mac(m.interface, mac);
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, mac, eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface, info);
				continue;
			} else {
				// BONUS: incremental calculation of checksum using a 16-bit field
				// composed by two 8-bit fields: protocol and ttl.
				uint16_t m, new_m;
				m = (ip_hdr->protocol << 8) | ip_hdr->ttl;
				new_m = (ip_hdr->protocol << 8) | (ip_hdr->ttl - 1);

				// decrementing the TTL
				ip_hdr->ttl--;

				// the new checksum
				ip_hdr->check = checksum - (~m) - new_m - 1;
			}

			// if the package is destined to the router = the interface on
			// which it reached the router, answer = reply to it.
			if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				if (ip_hdr->protocol == IPPROTO_ICMP) {
					// answering to the ICMP message by extracting the
					// ICMP header
					struct icmphdr *hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

					if (hdr->type == ICMP_ECHO) {
						send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m.interface, hdr->un.echo.id, hdr->un.echo.sequence);
						continue;
					}
				}
			}

			// finding "the best way out" = the best route using longest prefix match
			struct route_table_entry *entry = lpm(rtable, route_entries, ip_hdr->daddr);

			// if we have not found an entry in the routing table, the destination
			// does not exist / is unreachable. Send an appropriate ICMP error message
			if (!entry) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_DEST_UNREACH, 0, m.interface, info);
				continue;
			}
			
			// we need the MAC address of the next hop -> we need to inspect the ARP
			// table
			struct arp_entry *a_entry = get_arp_entry(arp_table, arp_entries, entry->next_hop);

			// we found an ARP entry in the router's cache, let's send the packet.
			if (a_entry) {
				get_interface_mac(entry->interface, mac);
				memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);

				memcpy(eth_hdr->ether_dhost, a_entry->mac, ETH_ALEN);
				m.interface = entry->interface;
				send_packet(&m);
			} else {
				// we didn't found the ARP entry corresponding to the next hop's IPv4
				// address, therefore we must create a new entry.

				// storing the package in a queue (for later)
				packet *m_copy = my_packet_strdup(&m);
				queue_enq(q, m_copy);
				
				// preparing the ethernet header for ARP request.
				memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN);
				get_interface_mac(entry->interface, mac);

				memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);

				// the new package is of ARP type (L2 field).
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// send the ARP request.
				send_arp(entry->next_hop, inet_addr(get_interface_ip(entry->interface)), eth_hdr, entry->interface, htons(ARPOP_REQUEST));
				continue;
			}
		}

		// Part 2: if the package is of ARP type.
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			// extract the ARP header
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload +
										sizeof(struct ether_header));

			// if we have an ARP request (for the router's interface), send a
			// reply containing the MAC of the corresponding interface.
			// -> I noticed later that I should have used the send_arp() function,
			// but this is a nice solution as well.
			if (arp_hdr->op == htons(ARPOP_REQUEST) && arp_hdr->tpa == inet_addr(get_interface_ip(m.interface))) {
				get_interface_mac(m.interface, mac);

				// replace the MAC addresses of the ethernet header
				memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ALEN);
				memcpy(arp_hdr->sha, mac, ETH_ALEN);

				arp_hdr->op = htons(ARPOP_REPLY);

				// swap the IPv4 addresses
				uint32_t aux_ip = arp_hdr->spa;
				arp_hdr->spa = arp_hdr->tpa;
				arp_hdr->tpa = aux_ip;

				// update L2 addresses
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
				memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);

				send_packet(&m);
			}

			// if the router receives an ARP reply
			if (arp_hdr->op == htons(ARPOP_REPLY) && arp_hdr->tpa == inet_addr(get_interface_ip(m.interface))) {
				// build a new ARP entry instance;
				struct arp_entry my_entry;
				my_entry.ip = arp_hdr->spa;
				memcpy(my_entry.mac, arp_hdr->sha, ETH_ALEN);

				// add the instance in the ARP table
				arp_table[arp_entries] = my_entry;
				arp_entries++;

				// if the ARP table is full, resize it. #defensiveprogramming
				if (arp_entries == arp_capacity) {
					arp_capacity *= 2;
					void *aux = (struct arp_entry *)realloc(arp_table, arp_capacity);
					DIE(!aux, "Reallocation of ARP table failed");
					arp_table = aux;
				}

				// Send the packages that were waiting for an ARP reply (that now know
				// where they should arrive, in terms of MAC addresses).
				while (!queue_empty(q)) {
					// peak = extract a pointer to the packet.
					packet *pack = (packet *)queue_peak(q);

					// extract the IPv4 header, get the best route once again
					// and send the packet.
					struct iphdr *header = (struct iphdr *)(pack->payload + sizeof(struct ether_header));
					struct route_table_entry *r_entry = lpm(rtable, route_entries, header->daddr);
					struct arp_entry *my_a_entry = get_arp_entry(arp_table, arp_entries, r_entry->next_hop);

					if (my_a_entry) {
						struct ether_header *h_header = (struct ether_header *)(pack->payload);
						memcpy(h_header->ether_dhost, my_a_entry->mac, ETH_ALEN);
						
						get_interface_mac(r_entry->interface, h_header->ether_shost);
						pack->interface = r_entry->interface;

						send_packet(pack);
						pack = queue_deq(q);
						free(pack);

						continue;
					}

					break;
				}
			}
		}
	}

	return 0;
}
