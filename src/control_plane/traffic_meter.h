/*
 * traffic_meter.h -- shared types and function declarations
 */
#ifndef TRAFFIC_METER_H
#define TRAFFIC_METER_H

/*
 * Subcommand identifiers
 */
enum {
	CMD_NONE = 0,
	CMD_LOAD,
	CMD_UNLOAD,
	CMD_ADD,
	CMD_DEL,
	CMD_IMPORT,
	CMD_LIST,
	CMD_SHOW,
};

/*
 * Parsed command-line state, shared between CLI parser and command implementations.
 */
struct traffic_meter_ctl {
	int		cmd;		/* CMD_* */

	/* load / unload */
	const char	*dev;		/* --dev <ifname> */
	const char	*object;	/* --object <xdp.o> */
	const char	*bpffs_pin;	/* --bpffs-pin <path> */

	/* add / del / show */
	const char	*ip_address;	/* --ip-address <IP or CIDR> */

	/* import */
	const char	*file;		/* --file <path.json> */
};

/*
 * Command implementations (traffic_meter_cmd.c)
 */
int do_load(struct traffic_meter_ctl *ctl);
int do_unload(struct traffic_meter_ctl *ctl);
int do_add(struct traffic_meter_ctl *ctl);
int do_del(struct traffic_meter_ctl *ctl);
int do_import(struct traffic_meter_ctl *ctl);
int do_list(struct traffic_meter_ctl *ctl);
int do_show(struct traffic_meter_ctl *ctl);

#endif /* TRAFFIC_METER_H */
