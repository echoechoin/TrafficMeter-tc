/*
 * traffic_meter -- BPF/TC based traffic statistics tool
 *
 * This file contains ONLY command-line parsing and subcommand dispatch.
 * Actual command implementations live in traffic_meter_cmd.c.
 *
 * Command-line style follows util-linux conventions.
 */

/* c.h must be first -- it defines _GNU_SOURCE before system headers */
#include "c.h"

#include <getopt.h>

#include "xalloc.h"
#include "strutils.h"
#include "traffic_meter.h"

static const char *cmd_names[] = {
	[CMD_NONE]   = "(none)",
	[CMD_LOAD]   = "load",
	[CMD_UNLOAD] = "unload",
	[CMD_ADD]    = "add",
	[CMD_DEL]    = "del",
	[CMD_IMPORT] = "import",
	[CMD_LIST]   = "list",
	[CMD_SHOW]   = "show",
	[CMD_CLEAR]  = "clear",
};

/* ------------------------------------------------------------------ */
/*  Usage / help                                                       */
/* ------------------------------------------------------------------ */

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *out = stdout;

	fputs(USAGE_HEADER, out);
	fprintf(out,
		" %s <command> [options]\n",
		program_invocation_short_name);

	fputs(USAGE_COMMANDS, out);
	fputs(" load                    load BPF program and attach to NIC\n", out);
	fputs(" unload                  detach BPF program from NIC\n", out);
	fputs(" add                     add an IP/CIDR rule\n", out);
	fputs(" del                     delete an IP/CIDR rule\n", out);
	fputs(" import                  import rules from a JSON file\n", out);
	fputs(" list                    list all current rules\n", out);
	fputs(" show                    show traffic statistics\n", out);
	fputs(" clear                   clear all traffic statistics (reset to zero)\n", out);

	fputs(USAGE_OPTIONS, out);
	fputs(" -d, --dev <ifname>      network interface (load/unload)\n", out);
	fputs(" -o, --object <file>     BPF object file path (load)\n", out);
	fputs(" -p, --bpffs-pin <path>  bpffs pin path (load)\n", out);
	fputs(" -a, --ip-address <addr> IP address or CIDR (add/del/show)\n", out);
	fputs(" -f, --file <path>       JSON rules file (import)\n", out);

	fputs(USAGE_SEPARATOR, out);
	fprintf(out, USAGE_HELP_OPTIONS(28));

	exit(EXIT_SUCCESS);
}

static void __attribute__((__noreturn__)) usage_cmd(const char *cmd)
{
	FILE *out = stdout;

	fputs(USAGE_HEADER, out);

	if (strcmp(cmd, "load") == 0) {
		fprintf(out, " %s load --dev <ifname> [--object <bpf.o>] [--bpffs-pin <path>]\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -d, --dev <ifname>      network interface to attach TC BPF\n", out);
		fputs(" -o, --object <file>     BPF object file (default: built-in path)\n", out);
		fputs(" -p, --bpffs-pin <path>  bpffs pin path for maps/program\n", out);
	} else if (strcmp(cmd, "unload") == 0) {
		fprintf(out, " %s unload --dev <ifname>\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -d, --dev <ifname>      network interface to detach TC BPF\n", out);
	} else if (strcmp(cmd, "add") == 0) {
		fprintf(out, " %s add --ip-address <IP or CIDR>\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -a, --ip-address <addr> IPv4/IPv6 address or CIDR\n", out);
	} else if (strcmp(cmd, "del") == 0) {
		fprintf(out, " %s del --ip-address <IP or CIDR>\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -a, --ip-address <addr> IPv4/IPv6 address or CIDR\n", out);
	} else if (strcmp(cmd, "import") == 0) {
		fprintf(out, " %s import --file <path.json>\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -f, --file <path>       JSON file with IP/CIDR rules\n", out);
	} else if (strcmp(cmd, "list") == 0) {
		fprintf(out, " %s list\n",
			program_invocation_short_name);
	} else if (strcmp(cmd, "show") == 0) {
		fprintf(out, " %s show [-H] [--ip-address <IP or CIDR>]\n",
			program_invocation_short_name);
		fputs(USAGE_OPTIONS, out);
		fputs(" -a, --ip-address <addr> show statistics for specific rule only\n", out);
		fputs(" -H, --human-readable    show bytes in human-readable format (KiB, MiB, GiB)\n", out);
	} else if (strcmp(cmd, "clear") == 0) {
		fprintf(out, " %s clear\n",
			program_invocation_short_name);
		fputs(" Clears all per-rule traffic statistics (resets counters to zero). Rules are unchanged.\n", out);
	}

	fputs(USAGE_SEPARATOR, out);
	fprintf(out, USAGE_HELP_OPTIONS(28));

	exit(EXIT_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  Command name resolution                                            */
/* ------------------------------------------------------------------ */

static int parse_command(const char *name)
{
	if (!name)
		return CMD_NONE;

	for (size_t i = CMD_LOAD; i <= CMD_CLEAR; i++) {
		if (strcmp(name, cmd_names[i]) == 0)
			return (int)i;
	}
	return CMD_NONE;
}

/* ------------------------------------------------------------------ */
/*  Main: parse subcommand, then getopt_long for options               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	struct traffic_meter_ctl ctl = {
		.cmd = CMD_NONE,
	};
	int c;

	static const struct option longopts[] = {
		{ "dev",            required_argument, NULL, 'd' },
		{ "object",         required_argument, NULL, 'o' },
		{ "bpffs-pin",      required_argument, NULL, 'p' },
		{ "ip-address",     required_argument, NULL, 'a' },
		{ "file",           required_argument, NULL, 'f' },
		{ "human-readable", no_argument,       NULL, 'H' },
		{ "version",        no_argument,       NULL, 'V' },
		{ "help",           no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	static const char *shortopts = "+d:o:p:a:f:HVh";

	/*
	 * First non-option argument is the subcommand.
	 * We peek at argv[1]; if it starts with '-' it is a global option
	 * (like --help or --version), otherwise it is a command name.
	 */
	if (argc < 2) {
		warnx("no command specified");
		errtryhelp(EXIT_FAILURE);
	}

	/* Handle global --help / --version before subcommand */
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
		usage();
	if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		print_version(EXIT_SUCCESS);

	/* Parse subcommand */
	ctl.cmd = parse_command(argv[1]);
	if (ctl.cmd == CMD_NONE) {
		warnx("unknown command: %s", argv[1]);
		errtryhelp(EXIT_FAILURE);
	}

	/* Shift argv so getopt sees only the options after the subcommand */
	argc--;
	argv++;
	optind = 1;

	while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			ctl.dev = optarg;
			break;
		case 'o':
			ctl.object = optarg;
			break;
		case 'p':
			ctl.bpffs_pin = optarg;
			break;
		case 'a':
			ctl.ip_address = optarg;
			break;
		case 'f':
			ctl.file = optarg;
			break;
		case 'H':
			ctl.human = 1;
			break;
		case 'V':
			print_version(EXIT_SUCCESS);
		case 'h':
			usage_cmd(cmd_names[ctl.cmd]);
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	/* Dispatch to command implementations in traffic_meter_cmd.c */
	switch (ctl.cmd) {
	case CMD_LOAD:
		return do_load(&ctl);
	case CMD_UNLOAD:
		return do_unload(&ctl);
	case CMD_ADD:
		return do_add(&ctl);
	case CMD_DEL:
		return do_del(&ctl);
	case CMD_IMPORT:
		return do_import(&ctl);
	case CMD_LIST:
		return do_list(&ctl);
	case CMD_SHOW:
		return do_show(&ctl);
	case CMD_CLEAR:
		return do_clear(&ctl);
	default:
		warnx("no command specified");
		errtryhelp(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
