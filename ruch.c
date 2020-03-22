#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define ETHERTYPE(x) { #x, ETH_P_##x }
static const struct {
	const char *name;
	uint16_t value;
} ethertypes[] = {
	ETHERTYPE(LOOP),
	ETHERTYPE(PUP),
	ETHERTYPE(PUPAT),
	ETHERTYPE(IP),
	ETHERTYPE(X25),
	ETHERTYPE(ARP),
	ETHERTYPE(BPQ),
	ETHERTYPE(IEEEPUP),
	ETHERTYPE(IEEEPUPAT),
	ETHERTYPE(DEC),
	ETHERTYPE(DNA_DL),
	ETHERTYPE(DNA_RC),
	ETHERTYPE(DNA_RT),
	ETHERTYPE(LAT),
	ETHERTYPE(DIAG),
	ETHERTYPE(CUST),
	ETHERTYPE(SCA),
	ETHERTYPE(TEB),
	ETHERTYPE(RARP),
	ETHERTYPE(ATALK),
	ETHERTYPE(AARP),
	ETHERTYPE(8021Q),
	ETHERTYPE(8021AD),
	ETHERTYPE(IPX),
	ETHERTYPE(IPV6),
	ETHERTYPE(PAUSE),
	ETHERTYPE(SLOW),
	ETHERTYPE(WCCP),
	ETHERTYPE(PPP_DISC),
	ETHERTYPE(PPP_SES),
	ETHERTYPE(MPLS_UC),
	ETHERTYPE(MPLS_MC),
	ETHERTYPE(ATMMPOA),
	ETHERTYPE(ATMFATE),
	ETHERTYPE(PAE),
	ETHERTYPE(AOE),
	ETHERTYPE(TIPC),
	ETHERTYPE(1588),
	ETHERTYPE(FCOE),
	ETHERTYPE(FIP),
	ETHERTYPE(EDSA),
	ETHERTYPE(802_3),
	ETHERTYPE(AX25),
	ETHERTYPE(ALL),
	ETHERTYPE(802_2),
	ETHERTYPE(SNAP),
	ETHERTYPE(DDCMP),
	ETHERTYPE(WAN_PPP),
	ETHERTYPE(PPP_MP),
	ETHERTYPE(LOCALTALK),
	ETHERTYPE(CAN),
	ETHERTYPE(PPPTALK),
	ETHERTYPE(TR_802_2),
	ETHERTYPE(MOBITEX),
	ETHERTYPE(CONTROL),
	ETHERTYPE(IRDA),
	ETHERTYPE(ECONET),
	ETHERTYPE(HDLC),
	ETHERTYPE(ARCNET),
	ETHERTYPE(DSA),
	ETHERTYPE(TRAILER),
	ETHERTYPE(PHONET),
	ETHERTYPE(IEEE802154),
};
static int ethertype_eq(const char *a, const char *b)
{
	unsigned int i = 0;

	if (strlen(a) != strlen(b))
		return 0;

	for (i = 0; i < strlen(a); ++i)
		if (tolower(a[i]) != tolower(b[i]))
			return 0;

	return 1;
}
static int ethertype_get(const char *ethertype)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(ethertypes); ++i)
		if (ethertype_eq(ethertypes[i].name, ethertype))
                  return ethertypes[i].value;

        return -1;
}

static void random_mac_addr(unsigned char *octet)
{
	unsigned int i = 0;

	for (i = 0; i < ETHER_ADDR_LEN; ++i)
		octet[i] = rand() % 250 + 10;
}

struct traffic_def {
	struct ethhdr ethhdr;
	int ifindex;
};

static void traffic_def_init(struct traffic_def *self)
{
	memset(self, 0, sizeof *self);

	random_mac_addr(self->ethhdr.h_dest);
	random_mac_addr(self->ethhdr.h_source);
}

static void traffic_def_exit(struct traffic_def *self)
{
}

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
			int type;

			arg = args_shift(args);
			if (!arg)
				break;

			type = ethertype_get(arg);
			if (type <= 0) {
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

	traffic_def_init(&def);

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

	printf("ruch: info: firing traffic...\n");
	generator_send(&generator, &def);

	args_exit(&args);
	traffic_def_exit(&def);
	generator_exit(&generator);

	return 0;
}
