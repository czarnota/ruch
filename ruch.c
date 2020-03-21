#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct traffic_def {
	struct ethhdr ethhdr;
	int ifindex;
};

struct generator {
	int fd;
};

static int generator_init(struct generator *self)
{
	self->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (self->fd < 0)
		return -1;

	return 0;
}

static void generator_send(struct generator *self, const struct traffic_def *def)
{
	struct sockaddr_ll addr = { 0 };
	ssize_t ret;

	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = def->ifindex;
	addr.sll_halen = ETHER_ADDR_LEN;
	addr.sll_protocol = def->ethhdr.h_proto;

	memcpy(addr.sll_addr,def->ethhdr.h_dest, sizeof def->ethhdr.h_dest);

	while (1) {
		ret = sendto(self->fd, &def->ethhdr, sizeof def->ethhdr, 0,
			     (const struct sockaddr *)&addr, sizeof addr);
		if (ret != sizeof def->ethhdr) {
			perror("ruch: err: sendto() failed");
			break;
		}
	}
}

static void generator_exit(struct generator *self)
{
	close(self->fd);
}

struct args {
	const char *const *argv;
	const char *const *end;
};

static void args_init(struct args *self, int argc, const char *const *argv)
{
	self->argv = argv;
	self->end = argv + argc;
}

const char *args_shift(struct args *self)
{
	const char *arg;

	if (self->argv >= self->end)
		return NULL;

	arg = *self->argv;

	self->argv++;

	return arg;
}

void args_unshift(struct args *self)
{
	self->argv--;
}

static void args_exit(struct args *self)
{
	return;
}

static int cmd_eth(struct traffic_def *def, struct args *args)
{
	const char *arg = NULL;
	struct ether_addr ether_addr;
	while (1) {
		arg = args_shift(args);
		if (!arg)
			break;

		if (strcmp(arg, "src") == 0) {
			arg = args_shift(args);
			if (!arg)
				break;

			if (!ether_aton_r(arg, &ether_addr)) {
				fprintf(stderr, "ruch: err: invalid MAC address passed as src\n");
				return 1;
			}

			memcpy(def->ethhdr.h_source, &ether_addr, sizeof def->ethhdr.h_source);

			continue;
		}
		if (strcmp(arg, "dst") == 0) {
			arg = args_shift(args);
			if (!arg)
				break;

			if (!ether_aton_r(arg, &ether_addr)) {
				fprintf(stderr, "ruch: err: invalid MAC address passed as dst\n");
				return 1;
			}

			memcpy(def->ethhdr.h_dest, &ether_addr, sizeof def->ethhdr.h_source);

			continue;
		}
		if (strcmp(arg, "type") == 0) {
			unsigned int type;

			arg = args_shift(args);
			if (!arg)
				break;

			if (1 != sscanf(arg, "%X", &type)) {
				fprintf(stderr, "ruch: err: invalid type\n");
				return 1;
			}

			def->ethhdr.h_proto = htons(type);

			continue;
		}

		args_unshift(args);
		break;
	}

	return 0;
}

static int cmd_dev(struct traffic_def *def, struct args *args)
{
	const char *arg = NULL;

	arg = args_shift(args);

	if (!arg)
		return 1; def->ifindex = if_nametoindex(arg);
	if (!def->ifindex) {
		perror("ruch: err: can't get ifindex");
		return 1;
	}

	return 0;
}

static const struct {
	const char *cmd;
	int (*doit)(struct traffic_def *def, struct args *args);
} cmds[] = {
	{
		.cmd = "eth",
		.doit = cmd_eth
	},
	{
		.cmd = "dev",
		.doit = cmd_dev
	}
};

int main(int argc, const char *const *argv)
{
	const char *cmd;
	unsigned int i = 0;
	struct args args;
	struct generator generator;
	struct traffic_def def = {0};
	int err;

	if (argc <= 1)
		return 0;

	err = generator_init(&generator);
	if (err) {
		perror("ruch: err: generator_init() failed");
		return 1;
	}

	printf("ruch: info: generator initialized\n");

	args_init(&args, argc, argv);

	cmd = args_shift(&args);

	while (1) {
nextcmd:
		cmd = args_shift(&args);
		if (!cmd)
			break;

		for (i = 0; i < ARRAY_SIZE(cmds); ++i) {
			if (strcmp(cmds[i].cmd, cmd) == 0) {
				cmds[i].doit(&def, &args);
				goto nextcmd;
			}
		}

		break;
	}


	printf("ruch: info: sending traffic...\n");
	generator_send(&generator, &def);

	args_exit(&args);
	generator_exit(&generator);

	return 0;
}
