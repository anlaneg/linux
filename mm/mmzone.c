// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats, zones and page flags
 */


#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>

/*取首个online的NUMA node对应的pglist_data*/
struct pglist_data *first_online_pgdat(void)
{
	return NODE_DATA(first_online_node);
}

/*取下个可用的pgdat*/
struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;/*没有下一个了*/
	return NODE_DATA(nid);
}

/*
 * next_zone - helper magic for for_each_zone()
 */
struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
	    /*zone未遍历完，仍自增*/
		zone++;
	else {
	    /*node对应的zone遍历完，这里跳至下一个node*/
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
		    /*使用此node上首个zone*/
			zone = pgdat->node_zones;
		else
		    /*所有zone均完成遍历，返回NULL*/
			zone = NULL;
	}
	return zone;
}

static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
#ifdef CONFIG_NUMA
	return node_isset(zonelist_node_idx(zref), *nodes);
#else
	return 1;
#endif /* CONFIG_NUMA */
}

/* Returns the next zone at or below highest_zoneidx in a zonelist */
struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	/*
	 * Find the next suitable zone to use for the allocation.
	 * Only filter based on nodemask if it's set
	 */
	if (unlikely(nodes == NULL))
		while (zonelist_zone_idx(z) > highest_zoneidx)
		    /*取z中合适type的*/
			z++;
	else
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
		    /*除当前z,还容许在mask中的zone*/
			z++;

	return z;
}

void lruvec_init(struct lruvec *lruvec)
{
	enum lru_list lru;

	memset(lruvec, 0, sizeof(struct lruvec));
	spin_lock_init(&lruvec->lru_lock);
	zswap_lruvec_state_init(lruvec);

	for_each_lru(lru)
		INIT_LIST_HEAD(&lruvec->lists[lru]);
	/*
	 * The "Unevictable LRU" is imaginary: though its size is maintained,
	 * it is never scanned, and unevictable pages are not threaded on it
	 * (so that their lru fields can be reused to hold mlock_count).
	 * Poison its list head, so that any operations on it would crash.
	 */
	list_del(&lruvec->lists[LRU_UNEVICTABLE]);

	lru_gen_init_lruvec(lruvec);
}

#if defined(CONFIG_NUMA_BALANCING) && !defined(LAST_CPUPID_NOT_IN_PAGE_FLAGS)
int folio_xchg_last_cpupid(struct folio *folio, int cpupid)
{
	unsigned long old_flags, flags;
	int last_cpupid;

	old_flags = READ_ONCE(folio->flags);
	do {
		flags = old_flags;
		last_cpupid = (flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK;

		flags &= ~(LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT);
		flags |= (cpupid & LAST_CPUPID_MASK) << LAST_CPUPID_PGSHIFT;
	} while (unlikely(!try_cmpxchg(&folio->flags, &old_flags, flags)));

	return last_cpupid;
}
#endif
