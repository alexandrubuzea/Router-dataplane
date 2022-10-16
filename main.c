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