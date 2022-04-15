// SPDX-License-Identifier: GPL-2.0-only
/*
 * count the number of connections matching an arbitrary key.
 *
 * (C) 2017 Red Hat GmbH
 * Author: Florian Westphal <fw@strlen.de>
 *
 * split from xt_connlimit.c:
 *   (c) 2000 Gerd Knorr <kraxel@bytesex.org>
 *   Nov 2002: Martin Bene <martin.bene@icomedias.com>:
 *		only ignore TIME_WAIT or gone connections
 *   (C) CC Computer Consultants GmbH, 2007
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_count.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_zones.h>

#define CONNCOUNT_SLOTS		256U

#define CONNCOUNT_GC_MAX_NODES	8
#define MAX_KEYLEN		5

/* we will save the tuples of all connections we care about */
struct nf_conncount_tuple {
	struct list_head		node;
	struct nf_conntrack_tuple	tuple;
	struct nf_conntrack_zone	zone;
	int				cpu;
	u32				jiffies32;
};

struct nf_conncount_rb {
	struct rb_node node;
	struct nf_conncount_list list;
	u32 key[MAX_KEYLEN];
	struct rcu_head rcu_head;
};

static spinlock_t nf_conncount_locks[CONNCOUNT_SLOTS] __cacheline_aligned_in_smp;

struct nf_conncount_data {
    /*key的长度*/
	unsigned int keylen;
	struct rb_root root[CONNCOUNT_SLOTS];
	/*所属的net namespace*/
	struct net *net;
	/*对应的work函数为tree_gc_worker*/
	struct work_struct gc_work;
	unsigned long pending_trees[BITS_TO_LONGS(CONNCOUNT_SLOTS)];
	unsigned int gc_tree;
};

static u_int32_t conncount_rnd __read_mostly;
static struct kmem_cache *conncount_rb_cachep __read_mostly;
static struct kmem_cache *conncount_conn_cachep __read_mostly;

/*忽略掉tcp的time_wait/close状态*/
static inline bool already_closed(const struct nf_conn *conn)
{
	if (nf_ct_protonum(conn) == IPPROTO_TCP)
		return conn->proto.tcp.state == TCP_CONNTRACK_TIME_WAIT ||
		       conn->proto.tcp.state == TCP_CONNTRACK_CLOSE;
	else
		return false;
}

/*a,b执行内存比对*/
static int key_diff(const u32 *a, const u32 *b, unsigned int klen)
{
	return memcmp(a, b, klen * sizeof(u32));
}

static void conn_free(struct nf_conncount_list *list,
		      struct nf_conncount_tuple *conn)
{
	lockdep_assert_held(&list->list_lock);

	list->count--;/*count数减少*/
	list_del(&conn->node);

	kmem_cache_free(conncount_conn_cachep, conn);
}

/*检查指定的conn是否在连接跟踪表中存在，如存在返回对应的tuple_hash,否则返回err*/
static const struct nf_conntrack_tuple_hash *
find_or_evict(struct net *net, struct nf_conncount_list *list,
	      struct nf_conncount_tuple *conn)
{
	const struct nf_conntrack_tuple_hash *found;
	unsigned long a, b;
	/*取当前cpu*/
	int cpu = raw_smp_processor_id();
	u32 age;

	/*在连接跟踪表中查询指定conn*/
	found = nf_conntrack_find_get(net, &conn->zone, &conn->tuple);
	if (found)
		return found;

	/*连接跟踪表中不再有此conn,释放此conn*/
	b = conn->jiffies32;
	a = (u32)jiffies;

	/* conn might have been added just before by another cpu and
	 * might still be unconfirmed.  In this case, nf_conntrack_find()
	 * returns no result.  Thus only evict if this cpu added the
	 * stale entry or if the entry is older than two jiffies.
	 */
	age = a - b;
	if (conn->cpu == cpu || age >= 2) {
	    /*自链表上移除掉此conn*/
		conn_free(list, conn);
		return ERR_PTR(-ENOENT);
	}

	return ERR_PTR(-EAGAIN);
}

static int __nf_conncount_add(struct net *net,
			      struct nf_conncount_list *list,
			      const struct nf_conntrack_tuple *tuple,
			      const struct nf_conntrack_zone *zone)
{
	const struct nf_conntrack_tuple_hash *found;
	struct nf_conncount_tuple *conn, *conn_n;
	struct nf_conn *found_ct;
	unsigned int collect = 0;

	/*当前我们需要添加给定的tuple,在添加之前我们检查下list中保存的ct还在连接跟踪表中存在（这个实现太难受了）*/
	/* check the saved connections */
	list_for_each_entry_safe(conn, conn_n, &list->head, node) {
		if (collect > CONNCOUNT_GC_MAX_NODES)
		    /*本次维护数量超限，退出（bug:如果这样直接退出，则添加的内容可能会重复）*/
			break;

		found = find_or_evict(net, list, conn);
		if (IS_ERR(found)) {
		    /*conn在连接跟踪表上已不存在*/
			/* Not found, but might be about to be confirmed */
			if (PTR_ERR(found) == -EAGAIN) {
				if (nf_ct_tuple_equal(&conn->tuple, tuple) &&
				    nf_ct_zone_id(&conn->zone, conn->zone.dir) ==
				    nf_ct_zone_id(zone, zone->dir))
				    /*连接表里没有，但我们接下来要填加的恰好是它，故直接返回认为添加成功*/
					return 0; /* already exists */
			} else {
			    /*这种我们已经删除了*/
				collect++;
			}
			continue;
		}

		found_ct = nf_ct_tuplehash_to_ctrack(found);

		if (nf_ct_tuple_equal(&conn->tuple, tuple) &&
		    nf_ct_zone_equal(found_ct, zone, zone->dir)) {
		    /*这种ct已存在，不再重复加入*/
			/*
			 * We should not see tuples twice unless someone hooks
			 * this into a table without "-p tcp --syn".
			 *
			 * Attempt to avoid a re-add in this case.
			 */
			nf_ct_put(found_ct);
			return 0;
		} else if (already_closed(found_ct)) {
		    /*这种ct已关闭，不计入，减少计数，释放found_ct*/
			/*
			 * we do not care about connections which are
			 * closed already -> ditch it
			 */
			nf_ct_put(found_ct);
			/*移除掉此conn*/
			conn_free(list, conn);
			collect++;
			continue;
		}

		nf_ct_put(found_ct);
	}

	/*计数overflow,跳过*/
	if (WARN_ON_ONCE(list->count > INT_MAX))
		return -EOVERFLOW;

	/*增加此conn，并将其加入到list中*/
	conn = kmem_cache_alloc(conncount_conn_cachep, GFP_ATOMIC);
	if (conn == NULL)
		return -ENOMEM;

	conn->tuple = *tuple;
	conn->zone = *zone;
	conn->cpu = raw_smp_processor_id();
	conn->jiffies32 = (u32)jiffies;
	/*这个ct需要添加进list*/
	list_add_tail(&conn->node, &list->head);
	/*总数增加*/
	list->count++;
	return 0;
}

/*向list添加此tuple*/
int nf_conncount_add(struct net *net,
		     struct nf_conncount_list *list,
		     const struct nf_conntrack_tuple *tuple,
		     const struct nf_conntrack_zone *zone)
{
	int ret;

	/* check the saved connections */
	spin_lock_bh(&list->list_lock);
	/*执行tuple添加*/
	ret = __nf_conncount_add(net, list, tuple, zone);
	spin_unlock_bh(&list->list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_conncount_add);

void nf_conncount_list_init(struct nf_conncount_list *list)
{
	spin_lock_init(&list->list_lock);
	INIT_LIST_HEAD(&list->head);
	list->count = 0;
}
EXPORT_SYMBOL_GPL(nf_conncount_list_init);

/* Return true if the list is empty. Must be called with BH disabled. */
bool nf_conncount_gc_list(struct net *net,
			  struct nf_conncount_list *list)
{
	const struct nf_conntrack_tuple_hash *found;
	struct nf_conncount_tuple *conn, *conn_n;
	struct nf_conn *found_ct;
	unsigned int collected = 0;
	bool ret = false;

	/* don't bother if other cpu is already doing GC */
	if (!spin_trylock(&list->list_lock))
		return false;

	list_for_each_entry_safe(conn, conn_n, &list->head, node) {
		found = find_or_evict(net, list, conn);
		if (IS_ERR(found)) {
		    /*没有找到此ct,collected增加*/
			if (PTR_ERR(found) == -ENOENT)
				collected++;
			continue;
		}

		found_ct = nf_ct_tuplehash_to_ctrack(found);
		if (already_closed(found_ct)) {
			/*
			 * we do not care about connections which are
			 * closed already -> ditch it
			 */
			nf_ct_put(found_ct);
			/*此ct被关闭，移除它*/
			conn_free(list, conn);
			collected++;
			continue;
		}

		nf_ct_put(found_ct);
		if (collected > CONNCOUNT_GC_MAX_NODES)
		    /*有较多的node需要释放，跳出检查*/
			break;
	}

	if (!list->count)
		ret = true;
	spin_unlock(&list->list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_conncount_gc_list);

static void __tree_nodes_free(struct rcu_head *h)
{
	struct nf_conncount_rb *rbconn;

	rbconn = container_of(h, struct nf_conncount_rb, rcu_head);
	kmem_cache_free(conncount_rb_cachep, rbconn);
}

/* caller must hold tree nf_conncount_locks[] lock */
static void tree_nodes_free(struct rb_root *root,
			    struct nf_conncount_rb *gc_nodes[],
			    unsigned int gc_count)
{
	struct nf_conncount_rb *rbconn;

	/*移除已经为空的rbconn*/
	while (gc_count) {
		rbconn = gc_nodes[--gc_count];
		spin_lock(&rbconn->list.list_lock);
		if (!rbconn->list.count) {
			rb_erase(&rbconn->node, root);
			call_rcu(&rbconn->rcu_head, __tree_nodes_free);
		}
		spin_unlock(&rbconn->list.list_lock);
	}
}

static void schedule_gc_worker(struct nf_conncount_data *data, int tree)
{
	set_bit(tree, data->pending_trees);
	schedule_work(&data->gc_work);
}

/*向data对应的树上添加指定tuple节点*/
static unsigned int
insert_tree(struct net *net,
	    struct nf_conncount_data *data,
	    struct rb_root *root,/*红黑树根节点*/
	    unsigned int hash,/*key对应的hashcode*/
	    const u32 *key,/*tuple对应的key*/
	    const struct nf_conntrack_tuple *tuple,/*待加入的tuple*/
	    const struct nf_conntrack_zone *zone)
{
	struct nf_conncount_rb *gc_nodes[CONNCOUNT_GC_MAX_NODES];
	struct rb_node **rbnode, *parent;
	struct nf_conncount_rb *rbconn;
	struct nf_conncount_tuple *conn;
	unsigned int count = 0, gc_count = 0;
	u8 keylen = data->keylen;
	bool do_gc = true;

	/*锁此key对应的桶*/
	spin_lock_bh(&nf_conncount_locks[hash]);
restart:
	parent = NULL;
	rbnode = &(root->rb_node);/*取红黑树根节点*/
	while (*rbnode) {
		int diff;
		/*取rbnode对应的rbconn*/
		rbconn = rb_entry(*rbnode, struct nf_conncount_rb, node);

		parent = *rbnode;
		diff = key_diff(key, rbconn->key, keylen);
		if (diff < 0) {
			rbnode = &((*rbnode)->rb_left);
		} else if (diff > 0) {
			rbnode = &((*rbnode)->rb_right);
		} else {
		    /*查找到合适的添加位置，将tuple添加到rbconn->list*/
			int ret;

			ret = nf_conncount_add(net, &rbconn->list, tuple, zone);
			if (ret)
			    /*添加失败*/
				count = 0; /* hotdrop */
			else
			    /*添加成功,取当前链表上的count*/
				count = rbconn->list.count;
			tree_nodes_free(root, gc_nodes, gc_count);
			/*处理完成，退出*/
			goto out_unlock;
		}

		if (gc_count >= ARRAY_SIZE(gc_nodes))
			continue;

		if (do_gc && nf_conncount_gc_list(net, &rbconn->list))
		    /*此rbconn->list已为空，需要移除，这里先记录*/
			gc_nodes[gc_count++] = rbconn;
	}

	if (gc_count) {
	    /*移除已经为空的rbconn*/
		tree_nodes_free(root, gc_nodes, gc_count);
		/*触发gc worker*/
		schedule_gc_worker(data, hash);
		gc_count = 0;
		do_gc = false;
		goto restart;
	}

	/*rbnode节点为空，在此位置初始化，并添加首个元素*/
	/* expected case: match, insert new node */
	rbconn = kmem_cache_alloc(conncount_rb_cachep, GFP_ATOMIC);
	if (rbconn == NULL)
		goto out_unlock;

	conn = kmem_cache_alloc(conncount_conn_cachep, GFP_ATOMIC);
	if (conn == NULL) {
		kmem_cache_free(conncount_rb_cachep, rbconn);
		goto out_unlock;
	}

	conn->tuple = *tuple;
	conn->zone = *zone;
	memcpy(rbconn->key, key, sizeof(u32) * keylen);

	nf_conncount_list_init(&rbconn->list);
	list_add(&conn->node, &rbconn->list.head);
	count = 1;/*首次添加计数为1*/
	rbconn->list.count = count;

	rb_link_node_rcu(&rbconn->node, parent, rbnode);
	rb_insert_color(&rbconn->node, root);
out_unlock:
	spin_unlock_bh(&nf_conncount_locks[hash]);
	return count;
}

/*获取链接跟踪计数*/
static unsigned int
count_tree(struct net *net,
	   struct nf_conncount_data *data,
	   const u32 *key/*查询用的key*/,
	   const struct nf_conntrack_tuple *tuple/*要添加的元组*/,
	   const struct nf_conntrack_zone *zone)
{
	struct rb_root *root;
	struct rb_node *parent;
	struct nf_conncount_rb *rbconn;
	unsigned int hash;
	/*匹配用的key的大小*/
	u8 keylen = data->keylen;

	/*计算key的hash*/
	hash = jhash2(key, data->keylen, conncount_rnd) % CONNCOUNT_SLOTS;
	/*确定key对应的根节点*/
	root = &data->root[hash];

	/*取红黑树根节点*/
	parent = rcu_dereference_raw(root->rb_node);
	while (parent) {
		int diff;

		/*取parent节点对应的nf_conncount_rb结构体*/
		rbconn = rb_entry(parent, struct nf_conncount_rb, node);

		diff = key_diff(key, rbconn->key, keylen);
		if (diff < 0) {
		    /*key较小，走左分支*/
			parent = rcu_dereference_raw(parent->rb_left);
		} else if (diff > 0) {
			parent = rcu_dereference_raw(parent->rb_right);
		} else {
		    /*遇到与待查询的key相等的情况*/
			int ret;

			if (!tuple) {
			    /*没有指定要匹配的tuple,直接计算count*/
				nf_conncount_gc_list(net, &rbconn->list);
				return rbconn->list.count;
			}

			/*加锁保存此链表*/
			spin_lock_bh(&rbconn->list.list_lock);
			/* Node might be about to be free'd.
			 * We need to defer to insert_tree() in this case.
			 */
			if (rbconn->list.count == 0) {
			    /*此链已为空，跳到insert_tree进行处理*/
				spin_unlock_bh(&rbconn->list.list_lock);
				break;
			}

			/* same source network -> be counted! */
			/*执行加入*/
			ret = __nf_conncount_add(net, &rbconn->list, tuple, zone);
			spin_unlock_bh(&rbconn->list.list_lock);
			if (ret)
				return 0; /* hotdrop */
			else
				return rbconn->list.count;
		}
	}

	if (!tuple)
	    /*没有查找到此key,也未指定tuple,不进行添加，直接返回0*/
		return 0;

	/*没有查询到此key,但指定了tuple,向树上添加此tuple*/
	return insert_tree(net, data, root, hash, key, tuple, zone);
}

/*此work的gc流程*/
static void tree_gc_worker(struct work_struct *work)
{
	struct nf_conncount_data *data = container_of(work, struct nf_conncount_data, gc_work);
	struct nf_conncount_rb *gc_nodes[CONNCOUNT_GC_MAX_NODES], *rbconn;
	struct rb_root *root;
	struct rb_node *node;
	unsigned int tree, next_tree, gc_count = 0;

	tree = data->gc_tree % CONNCOUNT_SLOTS;
	root = &data->root[tree];

	local_bh_disable();
	rcu_read_lock();
	for (node = rb_first(root); node != NULL; node = rb_next(node)) {
		rbconn = rb_entry(node, struct nf_conncount_rb, node);
		if (nf_conncount_gc_list(data->net, &rbconn->list))
			gc_count++;
	}
	rcu_read_unlock();
	local_bh_enable();

	cond_resched();

	spin_lock_bh(&nf_conncount_locks[tree]);
	if (gc_count < ARRAY_SIZE(gc_nodes))
		goto next; /* do not bother */

	gc_count = 0;
	node = rb_first(root);
	while (node != NULL) {
		rbconn = rb_entry(node, struct nf_conncount_rb, node);
		node = rb_next(node);

		if (rbconn->list.count > 0)
			continue;

		gc_nodes[gc_count++] = rbconn;
		if (gc_count >= ARRAY_SIZE(gc_nodes)) {
			tree_nodes_free(root, gc_nodes, gc_count);
			gc_count = 0;
		}
	}

	tree_nodes_free(root, gc_nodes, gc_count);
next:
	clear_bit(tree, data->pending_trees);

	next_tree = (tree + 1) % CONNCOUNT_SLOTS;
	next_tree = find_next_bit(data->pending_trees, CONNCOUNT_SLOTS, next_tree);

	if (next_tree < CONNCOUNT_SLOTS) {
		data->gc_tree = next_tree;
		schedule_work(work);
	}

	spin_unlock_bh(&nf_conncount_locks[tree]);
}

/* Count and return number of conntrack entries in 'net' with particular 'key'.
 * If 'tuple' is not null, insert it into the accounting data structure.
 * Call with RCU read lock.
 */
unsigned int nf_conncount_count(struct net *net,
				struct nf_conncount_data *data,
				const u32 *key/*查询用的Key*/,
				const struct nf_conntrack_tuple *tuple/*匹配用的元组*/,
				const struct nf_conntrack_zone *zone/*匹配用的zone*/)
{
	return count_tree(net, data, key, tuple, zone);
}
EXPORT_SYMBOL_GPL(nf_conncount_count);

struct nf_conncount_data *nf_conncount_init(struct net *net, unsigned int family,
					    unsigned int keylen)
{
	struct nf_conncount_data *data;
	int ret, i;

	if (keylen % sizeof(u32) ||
	    keylen / sizeof(u32) > MAX_KEYLEN ||
	    keylen == 0)
	    /*keylen没有4字节对齐 or keylen长度为0 or keylen长度大于32*/
		return ERR_PTR(-EINVAL);

	/*产生随机值*/
	net_get_random_once(&conncount_rnd, sizeof(conncount_rnd));

	/*申请conncount_data空间*/
	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	ret = nf_ct_netns_get(net, family);
	if (ret < 0) {
		kfree(data);
		return ERR_PTR(ret);
	}

	/*初始化data->root结构*/
	for (i = 0; i < ARRAY_SIZE(data->root); ++i)
		data->root[i] = RB_ROOT;

	data->keylen = keylen / sizeof(u32);
	data->net = net;
	INIT_WORK(&data->gc_work, tree_gc_worker);

	return data;
}
EXPORT_SYMBOL_GPL(nf_conncount_init);

void nf_conncount_cache_free(struct nf_conncount_list *list)
{
	struct nf_conncount_tuple *conn, *conn_n;

	list_for_each_entry_safe(conn, conn_n, &list->head, node)
		kmem_cache_free(conncount_conn_cachep, conn);
}
EXPORT_SYMBOL_GPL(nf_conncount_cache_free);

static void destroy_tree(struct rb_root *r)
{
	struct nf_conncount_rb *rbconn;
	struct rb_node *node;

	while ((node = rb_first(r)) != NULL) {
		rbconn = rb_entry(node, struct nf_conncount_rb, node);

		rb_erase(node, r);

		nf_conncount_cache_free(&rbconn->list);

		kmem_cache_free(conncount_rb_cachep, rbconn);
	}
}

void nf_conncount_destroy(struct net *net, unsigned int family,
			  struct nf_conncount_data *data)
{
	unsigned int i;

	cancel_work_sync(&data->gc_work);
	nf_ct_netns_put(net, family);

	for (i = 0; i < ARRAY_SIZE(data->root); ++i)
		destroy_tree(&data->root[i]);

	kfree(data);
}
EXPORT_SYMBOL_GPL(nf_conncount_destroy);

static int __init nf_conncount_modinit(void)
{
	int i;

	for (i = 0; i < CONNCOUNT_SLOTS; ++i)
		spin_lock_init(&nf_conncount_locks[i]);

	conncount_conn_cachep = kmem_cache_create("nf_conncount_tuple",
					   sizeof(struct nf_conncount_tuple),
					   0, 0, NULL);
	if (!conncount_conn_cachep)
		return -ENOMEM;

	conncount_rb_cachep = kmem_cache_create("nf_conncount_rb",
					   sizeof(struct nf_conncount_rb),
					   0, 0, NULL);
	if (!conncount_rb_cachep) {
		kmem_cache_destroy(conncount_conn_cachep);
		return -ENOMEM;
	}

	return 0;
}

static void __exit nf_conncount_modexit(void)
{
	kmem_cache_destroy(conncount_conn_cachep);
	kmem_cache_destroy(conncount_rb_cachep);
}

module_init(nf_conncount_modinit);
module_exit(nf_conncount_modexit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_AUTHOR("Florian Westphal <fw@strlen.de>");
MODULE_DESCRIPTION("netfilter: count number of connections matching a key");
MODULE_LICENSE("GPL");
