/*
 * traffic_meter_cmd.c -- command implementations
 *
 * Each do_xxx() function receives the parsed command-line state and
 * performs the corresponding action.
 */

#include "c.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <json-c/json.h>

#include "traffic_meter.h"
#include "traffic_meter_common.h"

/* Default path for the compiled BPF object */
#define DEFAULT_BPF_OBJECT	"traffic_meter.bpf.o"

/* Default bpffs pin directory */
#define DEFAULT_PIN_PATH	"/sys/fs/bpf/traffic_meter"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Resolve interface name to ifindex, or exit on failure.
 */
static unsigned int ifindex_or_err(const char *dev)
{
	unsigned int ifindex = if_nametoindex(dev);
	if (!ifindex)
		err(EXIT_FAILURE, "unknown interface: %s", dev);
	return ifindex;
}

/*
 * Ensure a directory exists (like `mkdir -p` for a single level).
 */
static void ensure_dir(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0)
		return;
	if (mkdir(path, 0755) && errno != EEXIST)
		err(EXIT_FAILURE, "cannot create directory: %s", path);
}

/* ------------------------------------------------------------------ */
/*  IP / CIDR parsing and validation                                   */
/* ------------------------------------------------------------------ */

/*
 * Address family detected from an IP/CIDR string.
 */
enum addr_family {
	ADDR_V4 = AF_INET,
	ADDR_V6 = AF_INET6,
};

/*
 * Parse an IP address or CIDR string (e.g. "10.0.0.0/24", "192.168.1.1",
 * "2001:db8::1", "2001:db8::/32") and populate either an lpm_v4_key or
 * lpm_v6_key.
 *
 * Returns:
 *   ADDR_V4 -- *v4 is filled, *v6 is untouched.
 *   ADDR_V6 -- *v6 is filled, *v4 is untouched.
 *   -1      -- parse error.
 */
static int parse_ip_cidr(const char *str,
			 struct lpm_v4_key *v4,
			 struct lpm_v6_key *v6)
{
	char buf[INET6_ADDRSTRLEN + 1];
	const char *slash;
	unsigned long prefix;
	int af;

	if (!str || !*str)
		return -1;

	/* Split address and optional /prefix */
	slash = strchr(str, '/');

	size_t addr_len = slash ? (size_t)(slash - str) : strlen(str);
	if (addr_len >= sizeof(buf))
		return -1;
	memcpy(buf, str, addr_len);
	buf[addr_len] = '\0';

	/* Detect address family by trying inet_pton for v4 then v6 */
	unsigned char addr_bin[16];

	if (inet_pton(AF_INET, buf, addr_bin) == 1) {
		af = ADDR_V4;
	} else if (inet_pton(AF_INET6, buf, addr_bin) == 1) {
		af = ADDR_V6;
	} else {
		return -1;
	}

	/* Parse prefix length */
	unsigned int max_prefix = (af == ADDR_V4) ? 32 : 128;

	if (slash) {
		char *endp;
		errno = 0;
		prefix = strtoul(slash + 1, &endp, 10);
		if (errno || *endp != '\0' || prefix > max_prefix)
			return -1;
	} else {
		/* No /prefix means host address (/32 or /128) */
		prefix = max_prefix;
	}

	/* Validate: bits beyond prefix must be zero */
	unsigned int addr_bytes = (af == ADDR_V4) ? 4 : 16;
	for (unsigned int bit = (unsigned int)prefix; bit < addr_bytes * 8; bit++) {
		unsigned int byte_idx = bit / 8;
		unsigned int bit_idx  = 7 - (bit % 8);
		if (addr_bin[byte_idx] & (1u << bit_idx))
			return -1;  /* host bits set in network address */
	}

	/* Fill the appropriate key struct */
	if (af == ADDR_V4) {
		memset(v4, 0, sizeof(*v4));
		v4->prefixlen = (__u32)prefix;
		memcpy(v4->addr, addr_bin, 4);
	} else {
		memset(v6, 0, sizeof(*v6));
		v6->prefixlen = (__u32)prefix;
		memcpy(v6->addr, addr_bin, 16);
	}

	return af;
}

/*
 * Open a pinned BPF map by name from the pin directory.
 * Returns fd >= 0 on success, or exits on failure.
 */
static int open_pinned_map(const char *pin_path, const char *map_name)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", pin_path, map_name);
	fd = bpf_obj_get(path);
	if (fd < 0)
		err(EXIT_FAILURE, "cannot open pinned map %s", path);
	return fd;
}

/* ------------------------------------------------------------------ */
/*  load                                                               */
/* ------------------------------------------------------------------ */

/*
 * Check whether maps are already pinned (i.e. a previous load has been
 * done).  Returns 1 if the pin directory exists and contains at least
 * one map file, 0 otherwise.
 */
static int maps_already_pinned(const char *pin_path)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/rules_v4", pin_path);
	return access(path, F_OK) == 0;
}

int do_load(struct traffic_meter_ctl *ctl)
{
	const char *obj_path  = ctl->object   ? ctl->object   : DEFAULT_BPF_OBJECT;
	const char *pin_path  = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *map;
	int prog_fd;
	unsigned int ifindex;
	int ret;
	int reuse = maps_already_pinned(pin_path);

	if (!ctl->dev) {
		warnx("load: --dev is required");
		errtryhelp(EXIT_FAILURE);
	}

	ifindex = ifindex_or_err(ctl->dev);

	/* 1. Open BPF object file */
	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj)
		err(EXIT_FAILURE, "failed to open BPF object: %s", obj_path);

	/*
	 * 2. If maps are already pinned (from a previous load on another
	 *    interface), tell libbpf to reuse them.  bpf_map__set_pin_path()
	 *    before load causes libbpf to open the existing pinned fd via
	 *    BPF_OBJ_GET instead of creating a new map.
	 */
	if (reuse) {
		bpf_object__for_each_map(map, obj) {
			char path[PATH_MAX];
			snprintf(path, sizeof(path), "%s/%s",
				 pin_path, bpf_map__name(map));
			ret = bpf_map__set_pin_path(map, path);
			if (ret) {
				bpf_object__close(obj);
				errx(EXIT_FAILURE,
				     "failed to set pin path for map %s",
				     bpf_map__name(map));
			}
		}
	}

	/* 3. Load BPF program + maps into kernel */
	ret = bpf_object__load(obj);
	if (ret) {
		bpf_object__close(obj);
		errx(EXIT_FAILURE, "failed to load BPF object: %s (err=%d)",
		     obj_path, ret);
	}

	/* 4. Find the XDP program (first program in the object) */
	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		bpf_object__close(obj);
		errx(EXIT_FAILURE, "no BPF program found in %s", obj_path);
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		bpf_object__close(obj);
		errx(EXIT_FAILURE, "invalid BPF program fd");
	}

	/* 5. Attach XDP program to network interface */
	ret = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
	if (ret) {
		bpf_object__close(obj);
		errx(EXIT_FAILURE, "failed to attach XDP to %s (ifindex=%u, err=%d)",
		     ctl->dev, ifindex, ret);
	}

	/* 6. Pin maps to bpffs (first load only; reuse skips this) */
	if (!reuse) {
		ensure_dir(pin_path);
		ret = bpf_object__pin_maps(obj, pin_path);
		if (ret) {
			bpf_xdp_detach(ifindex, 0, NULL);
			bpf_object__close(obj);
			errx(EXIT_FAILURE, "failed to pin maps to %s (err=%d)",
			     pin_path, ret);
		}
	}

	if (reuse)
		printf("loaded XDP on %s (ifindex=%u), reusing maps at %s\n",
		       ctl->dev, ifindex, pin_path);
	else
		printf("loaded XDP on %s (ifindex=%u), maps pinned at %s\n",
		       ctl->dev, ifindex, pin_path);

	/*
	 * Close the bpf_object handle.  The kernel holds references to the
	 * loaded program (via XDP attachment) and the pinned maps, so they
	 * remain alive after we close.
	 */
	bpf_object__close(obj);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  unload                                                             */
/* ------------------------------------------------------------------ */

int do_unload(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	unsigned int ifindex;
	int ret;

	if (!ctl->dev) {
		warnx("unload: --dev is required");
		errtryhelp(EXIT_FAILURE);
	}

	ifindex = ifindex_or_err(ctl->dev);

	/* 1. Detach XDP from the interface */
	ret = bpf_xdp_detach(ifindex, 0, NULL);
	if (ret)
		warnx("failed to detach XDP from %s (err=%d), continuing cleanup",
		      ctl->dev, ret);
	else
		printf("detached XDP from %s (ifindex=%u)\n",
		       ctl->dev, ifindex);

	/* 2. Unpin maps -- remove pinned files from bpffs */
	struct {
		const char *name;
	} map_names[] = {
		{ "rules_v4" },
		{ "rules_v6" },
		{ "stats_v4" },
		{ "stats_v6" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", pin_path, map_names[i].name);
		if (unlink(path) && errno != ENOENT)
			warn("failed to unpin %s", path);
	}

	/* Try removing the pin directory itself (will fail if not empty) */
	rmdir(pin_path);

	printf("unloaded, maps unpinned from %s\n", pin_path);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  add / del                                                          */
/* ------------------------------------------------------------------ */

/*
 * Create a zero-valued per-CPU stats entry for the given rule key.
 * This ensures `stats` shows the rule even before any traffic hits it.
 */
static void create_zero_stats(int stats_fd, const void *key, int ncpus)
{
	size_t val_sz = (size_t)ncpus * sizeof(struct traffic_stats);
	struct traffic_stats *zeros = calloc(1, val_sz);
	if (!zeros)
		err(EXIT_FAILURE, "calloc");

	/* BPF_NOEXIST: don't overwrite if the entry already exists
	 * (in case the rule is re-added while traffic is flowing). */
	bpf_map_update_elem(stats_fd, key, zeros, BPF_NOEXIST);
	free(zeros);
}

int do_add(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	struct lpm_v4_key v4 = {};
	struct lpm_v6_key v6 = {};
	int af, fd_rules, fd_stats, ret, ncpus;

	if (!ctl->ip_address) {
		warnx("add: --ip-address is required");
		errtryhelp(EXIT_FAILURE);
	}

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0)
		errx(EXIT_FAILURE, "failed to get number of CPUs: %d", ncpus);

	af = parse_ip_cidr(ctl->ip_address, &v4, &v6);
	if (af < 0)
		errx(EXIT_FAILURE, "invalid IP address or CIDR: %s",
		     ctl->ip_address);

	if (af == ADDR_V4) {
		__u32 prefix = v4.prefixlen;

		fd_rules = open_pinned_map(pin_path, "rules_v4");
		ret = bpf_map_update_elem(fd_rules, &v4, &prefix, BPF_ANY);
		close(fd_rules);
		if (ret)
			err(EXIT_FAILURE, "failed to add rule %s",
			    ctl->ip_address);

		fd_stats = open_pinned_map(pin_path, "stats_v4");
		create_zero_stats(fd_stats, &v4, ncpus);
		close(fd_stats);

		printf("added IPv4 rule: %s\n", ctl->ip_address);
	} else {
		__u32 prefix = v6.prefixlen;

		fd_rules = open_pinned_map(pin_path, "rules_v6");
		ret = bpf_map_update_elem(fd_rules, &v6, &prefix, BPF_ANY);
		close(fd_rules);
		if (ret)
			err(EXIT_FAILURE, "failed to add rule %s",
			    ctl->ip_address);

		fd_stats = open_pinned_map(pin_path, "stats_v6");
		create_zero_stats(fd_stats, &v6, ncpus);
		close(fd_stats);

		printf("added IPv6 rule: %s\n", ctl->ip_address);
	}

	return 0;
}

int do_del(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	struct lpm_v4_key v4 = {};
	struct lpm_v6_key v6 = {};
	int af, fd_rules, fd_stats, ret;

	if (!ctl->ip_address) {
		warnx("del: --ip-address is required");
		errtryhelp(EXIT_FAILURE);
	}

	af = parse_ip_cidr(ctl->ip_address, &v4, &v6);
	if (af < 0)
		errx(EXIT_FAILURE, "invalid IP address or CIDR: %s",
		     ctl->ip_address);

	if (af == ADDR_V4) {
		fd_rules = open_pinned_map(pin_path, "rules_v4");
		ret = bpf_map_delete_elem(fd_rules, &v4);
		close(fd_rules);
		if (ret)
			err(EXIT_FAILURE, "failed to delete rule %s",
			    ctl->ip_address);

		fd_stats = open_pinned_map(pin_path, "stats_v4");
		bpf_map_delete_elem(fd_stats, &v4); /* best-effort */
		close(fd_stats);

		printf("deleted IPv4 rule: %s\n", ctl->ip_address);
	} else {
		fd_rules = open_pinned_map(pin_path, "rules_v6");
		ret = bpf_map_delete_elem(fd_rules, &v6);
		close(fd_rules);
		if (ret)
			err(EXIT_FAILURE, "failed to delete rule %s",
			    ctl->ip_address);

		fd_stats = open_pinned_map(pin_path, "stats_v6");
		bpf_map_delete_elem(fd_stats, &v6); /* best-effort */
		close(fd_stats);

		printf("deleted IPv6 rule: %s\n", ctl->ip_address);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/*  import                                                             */
/* ------------------------------------------------------------------ */

/*
 * Add a single rule from an IP/CIDR string into the appropriate pinned
 * rule map and create a zero-valued stats entry.
 * Returns 0 on success, -1 on parse error, or exits on BPF map error.
 */
static int import_one_rule(const char *str,
			   int fd_rules_v4, int fd_rules_v6,
			   int fd_stats_v4, int fd_stats_v6,
			   int ncpus)
{
	struct lpm_v4_key v4 = {};
	struct lpm_v6_key v6 = {};
	int af, ret;

	af = parse_ip_cidr(str, &v4, &v6);
	if (af < 0)
		return -1;

	if (af == ADDR_V4) {
		__u32 prefix = v4.prefixlen;
		ret = bpf_map_update_elem(fd_rules_v4, &v4, &prefix, BPF_ANY);
		if (ret)
			err(EXIT_FAILURE, "failed to add rule %s", str);
		create_zero_stats(fd_stats_v4, &v4, ncpus);
	} else {
		__u32 prefix = v6.prefixlen;
		ret = bpf_map_update_elem(fd_rules_v6, &v6, &prefix, BPF_ANY);
		if (ret)
			err(EXIT_FAILURE, "failed to add rule %s", str);
		create_zero_stats(fd_stats_v6, &v6, ncpus);
	}

	return 0;
}

int do_import(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	struct json_object *root;
	int fd_rules_v4, fd_rules_v6, fd_stats_v4, fd_stats_v6;
	int ncpus;
	int added = 0, skipped = 0;

	if (!ctl->file) {
		warnx("import: --file is required");
		errtryhelp(EXIT_FAILURE);
	}

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0)
		errx(EXIT_FAILURE, "failed to get number of CPUs: %d", ncpus);

	/* 1. Parse JSON file */
	root = json_object_from_file(ctl->file);
	if (!root)
		errx(EXIT_FAILURE, "failed to parse JSON file: %s", ctl->file);

	if (!json_object_is_type(root, json_type_array)) {
		json_object_put(root);
		errx(EXIT_FAILURE, "JSON root must be an array: %s", ctl->file);
	}

	size_t n = json_object_array_length(root);
	if (n == 0) {
		json_object_put(root);
		warnx("import: empty array in %s, nothing to do", ctl->file);
		return 0;
	}

	/* 2. Open pinned maps (rules + stats) */
	fd_rules_v4 = open_pinned_map(pin_path, "rules_v4");
	fd_rules_v6 = open_pinned_map(pin_path, "rules_v6");
	fd_stats_v4 = open_pinned_map(pin_path, "stats_v4");
	fd_stats_v6 = open_pinned_map(pin_path, "stats_v6");

	/* 3. Iterate array and add each rule */
	for (size_t i = 0; i < n; i++) {
		struct json_object *elem = json_object_array_get_idx(root, i);

		if (!json_object_is_type(elem, json_type_string)) {
			warnx("import: entry [%zu] is not a string, skipping", i);
			skipped++;
			continue;
		}

		const char *str = json_object_get_string(elem);
		if (import_one_rule(str,
				    fd_rules_v4, fd_rules_v6,
				    fd_stats_v4, fd_stats_v6,
				    ncpus) < 0) {
			warnx("import: invalid IP/CIDR at [%zu]: %s, skipping",
			      i, str);
			skipped++;
			continue;
		}

		added++;
	}

	close(fd_rules_v4);
	close(fd_rules_v6);
	close(fd_stats_v4);
	close(fd_stats_v6);
	json_object_put(root);

	printf("imported %d rule(s) from %s", added, ctl->file);
	if (skipped)
		printf(" (%d skipped)", skipped);
	printf("\n");

	return 0;
}

/* ------------------------------------------------------------------ */
/*  list / stats                                                       */
/* ------------------------------------------------------------------ */

/*
 * Format an lpm_v4_key as "A.B.C.D/prefix" into buf.
 * If prefix == 32, omit the /prefix suffix for readability.
 */
static void fmt_v4_key(const struct lpm_v4_key *key, char *buf, size_t len)
{
	char addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, key->addr, addr, sizeof(addr));
	if (key->prefixlen == 32)
		snprintf(buf, len, "%s", addr);
	else
		snprintf(buf, len, "%s/%u", addr, key->prefixlen);
}

/*
 * Format an lpm_v6_key as "xxxx::xxxx/prefix" into buf.
 * If prefix == 128, omit the /prefix suffix.
 */
static void fmt_v6_key(const struct lpm_v6_key *key, char *buf, size_t len)
{
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, key->addr, addr, sizeof(addr));
	if (key->prefixlen == 128)
		snprintf(buf, len, "%s", addr);
	else
		snprintf(buf, len, "%s/%u", addr, key->prefixlen);
}

/*
 * Iterate an IPv4 LPM rule map and print all entries.
 * Returns the number of rules printed.
 */
static int list_rules_v4(int fd)
{
	struct lpm_v4_key key, next_key;
	char buf[INET_ADDRSTRLEN + 4]; /* "/32\0" */
	int count = 0;
	void *cur = NULL; /* NULL → get first key */

	while (bpf_map_get_next_key(fd, cur, &next_key) == 0) {
		fmt_v4_key(&next_key, buf, sizeof(buf));
		printf("  %s\n", buf);
		key = next_key;
		cur = &key;
		count++;
	}

	return count;
}

/*
 * Iterate an IPv6 LPM rule map and print all entries.
 * Returns the number of rules printed.
 */
static int list_rules_v6(int fd)
{
	struct lpm_v6_key key, next_key;
	char buf[INET6_ADDRSTRLEN + 5]; /* "/128\0" */
	int count = 0;
	void *cur = NULL;

	while (bpf_map_get_next_key(fd, cur, &next_key) == 0) {
		fmt_v6_key(&next_key, buf, sizeof(buf));
		printf("  %s\n", buf);
		key = next_key;
		cur = &key;
		count++;
	}

	return count;
}

int do_list(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	int fd_v4, fd_v6;
	int total = 0;

	fd_v4 = open_pinned_map(pin_path, "rules_v4");
	fd_v6 = open_pinned_map(pin_path, "rules_v6");

	printf("IPv4 rules:\n");
	total += list_rules_v4(fd_v4);

	printf("IPv6 rules:\n");
	total += list_rules_v6(fd_v6);

	close(fd_v4);
	close(fd_v6);

	if (!total)
		printf("(no rules)\n");
	else
		printf("total: %d rule(s)\n", total);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  stats                                                              */
/* ------------------------------------------------------------------ */

/*
 * Sum per-CPU traffic_stats values into a single aggregate.
 */
static void sum_percpu_stats(const struct traffic_stats *percpu, int ncpus,
			     struct traffic_stats *out)
{
	out->packets = 0;
	out->bytes   = 0;
	for (int i = 0; i < ncpus; i++) {
		out->packets += percpu[i].packets;
		out->bytes   += percpu[i].bytes;
	}
}

/*
 * Human-readable byte formatting: formats a byte count to a short
 * string with unit suffix (B, KiB, MiB, GiB, TiB).
 */
static const char *fmt_bytes(__u64 bytes, char *buf, size_t len)
{
	static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double val = (double)bytes;
	int u = 0;

	while (val >= 1024.0 && u < 4) {
		val /= 1024.0;
		u++;
	}

	if (u == 0)
		snprintf(buf, len, "%llu B", (unsigned long long)bytes);
	else
		snprintf(buf, len, "%.2f %s", val, units[u]);

	return buf;
}

/*
 * Print one stats line.
 */
static void print_stats_line(const char *addr_str,
			     const struct traffic_stats *agg)
{
	char bytes_buf[32];
	printf("  %-40s  packets: %-12llu  bytes: %s\n",
	       addr_str,
	       (unsigned long long)agg->packets,
	       fmt_bytes(agg->bytes, bytes_buf, sizeof(bytes_buf)));
}

/*
 * Iterate IPv4 stats map and print all entries.
 */
static int dump_stats_v4(int fd, int ncpus)
{
	struct lpm_v4_key key, next_key;
	struct traffic_stats *percpu;
	struct traffic_stats agg;
	char addr_buf[INET_ADDRSTRLEN + 4];
	int count = 0;
	void *cur = NULL;

	percpu = calloc((size_t)ncpus, sizeof(*percpu));
	if (!percpu)
		err(EXIT_FAILURE, "calloc");

	while (bpf_map_get_next_key(fd, cur, &next_key) == 0) {
		key = next_key;
		cur = &key;

		if (bpf_map_lookup_elem(fd, &next_key, percpu) != 0)
			continue;

		sum_percpu_stats(percpu, ncpus, &agg);
		fmt_v4_key(&next_key, addr_buf, sizeof(addr_buf));
		print_stats_line(addr_buf, &agg);
		count++;
	}

	free(percpu);
	return count;
}

/*
 * Iterate IPv6 stats map and print all entries.
 */
static int dump_stats_v6(int fd, int ncpus)
{
	struct lpm_v6_key key, next_key;
	struct traffic_stats *percpu;
	struct traffic_stats agg;
	char addr_buf[INET6_ADDRSTRLEN + 5];
	int count = 0;
	void *cur = NULL;

	percpu = calloc((size_t)ncpus, sizeof(*percpu));
	if (!percpu)
		err(EXIT_FAILURE, "calloc");

	while (bpf_map_get_next_key(fd, cur, &next_key) == 0) {
		key = next_key;
		cur = &key;

		if (bpf_map_lookup_elem(fd, &next_key, percpu) != 0)
			continue;

		sum_percpu_stats(percpu, ncpus, &agg);
		fmt_v6_key(&next_key, addr_buf, sizeof(addr_buf));
		print_stats_line(addr_buf, &agg);
		count++;
	}

	free(percpu);
	return count;
}

/*
 * Look up stats for a single exact rule key (IPv4).
 */
static int lookup_stats_v4(int fd, int ncpus,
			   const struct lpm_v4_key *key)
{
	struct traffic_stats *percpu;
	struct traffic_stats agg;
	char addr_buf[INET_ADDRSTRLEN + 4];

	percpu = calloc((size_t)ncpus, sizeof(*percpu));
	if (!percpu)
		err(EXIT_FAILURE, "calloc");

	if (bpf_map_lookup_elem(fd, key, percpu) != 0) {
		free(percpu);
		return 0;
	}

	sum_percpu_stats(percpu, ncpus, &agg);
	fmt_v4_key(key, addr_buf, sizeof(addr_buf));
	print_stats_line(addr_buf, &agg);

	free(percpu);
	return 1;
}

/*
 * Look up stats for a single exact rule key (IPv6).
 */
static int lookup_stats_v6(int fd, int ncpus,
			   const struct lpm_v6_key *key)
{
	struct traffic_stats *percpu;
	struct traffic_stats agg;
	char addr_buf[INET6_ADDRSTRLEN + 5];

	percpu = calloc((size_t)ncpus, sizeof(*percpu));
	if (!percpu)
		err(EXIT_FAILURE, "calloc");

	if (bpf_map_lookup_elem(fd, key, percpu) != 0) {
		free(percpu);
		return 0;
	}

	sum_percpu_stats(percpu, ncpus, &agg);
	fmt_v6_key(key, addr_buf, sizeof(addr_buf));
	print_stats_line(addr_buf, &agg);

	free(percpu);
	return 1;
}

int do_stats(struct traffic_meter_ctl *ctl)
{
	const char *pin_path = ctl->bpffs_pin ? ctl->bpffs_pin : DEFAULT_PIN_PATH;
	struct lpm_v4_key flt_v4 = {};
	struct lpm_v6_key flt_v6 = {};
	int fd_v4, fd_v6, ncpus;
	int total = 0;
	int filter_af = 0; /* 0 = show all */

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0)
		errx(EXIT_FAILURE, "failed to get number of CPUs: %d", ncpus);

	/* If --ip-address given, do an exact lookup for that rule key */
	if (ctl->ip_address) {
		int af = parse_ip_cidr(ctl->ip_address, &flt_v4, &flt_v6);
		if (af < 0)
			errx(EXIT_FAILURE, "invalid IP address or CIDR: %s",
			     ctl->ip_address);
		filter_af = af;
	}

	fd_v4 = open_pinned_map(pin_path, "stats_v4");
	fd_v6 = open_pinned_map(pin_path, "stats_v6");

	if (filter_af == ADDR_V4) {
		/* Exact lookup for a single IPv4 rule */
		total += lookup_stats_v4(fd_v4, ncpus, &flt_v4);
	} else if (filter_af == ADDR_V6) {
		/* Exact lookup for a single IPv6 rule */
		total += lookup_stats_v6(fd_v6, ncpus, &flt_v6);
	} else {
		/* Show all */
		printf("IPv4 stats:\n");
		total += dump_stats_v4(fd_v4, ncpus);

		printf("IPv6 stats:\n");
		total += dump_stats_v6(fd_v6, ncpus);
	}

	close(fd_v4);
	close(fd_v6);

	if (!total)
		printf("(no stats)\n");

	return 0;
}
