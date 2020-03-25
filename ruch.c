#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/ip.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define ARRAY_APPEND(array, item) append(&array, &array ## _cap, &array ## _len, (item), sizeof(*(item)))
#define ARRAY_CLEAR(array) do {\
		free((array)); \
		array = 0; \
		array ## _len = 0; \
		array ## _cap = 0; \
	} while (0)
#define ARRAY(type, name) \
	type *name; \
	unsigned int name ## _len; \
	unsigned int name ## _cap

static void append(void *ptr, unsigned int *cap, unsigned int *len, const void *item,
	    unsigned int size)
{
	void **array = (void **)ptr;

	if (*len == *cap) {
		if (*cap == 0)
			*cap = 8;
		else
			*cap *= 2;

		*array = realloc(*array, *cap * size);
		if (!*array)
			exit(1);
	}

	memcpy((unsigned char *)*array + *len * size, item, size);
	*len += 1;
}

struct vlanhdr {
	uint16_t tci;
	uint16_t proto;
} __attribute__((packed));

#define ETHERTYPE(x) { #x, ETH_P_##x }
#define ETHERTYPE_ALIAS(x, y) { #x, ETH_P_##y }
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
	ETHERTYPE_ALIAS(802.1Q, 8021Q),
	ETHERTYPE_ALIAS(802.1AD, 8021AD),
	ETHERTYPE_ALIAS(vlan, 8021Q),
	ETHERTYPE_ALIAS(qinq, 8021AD),
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

struct frame_def {
	unsigned char packet[1600];
	unsigned int i;
};

static void *frame_def_data(struct frame_def *self)
{
	return &self->packet[self->i];
}

static void *frame_def_begin(struct frame_def *self)
{
	return &self->packet[0];
}

static void frame_def_init(struct frame_def *self)
{
	struct ethhdr *ethhdr;

	memset(self, 0, sizeof *self);

	ethhdr = frame_def_data(self);

	random_mac_addr(ethhdr->h_dest);
	random_mac_addr(ethhdr->h_source);

	ethhdr->h_proto = htons(ETH_P_IP);
}

static void frame_def_push(struct frame_def *self, unsigned int size)
{
	self->i += size;
}

static void frame_def_pop(struct frame_def *self, unsigned int size)
{
	self->i -= size;
}

static void frame_def_exit(struct frame_def *self)
{
	return;
}

struct traffic_def {
	ARRAY(struct frame_def, frames);
	int ifindex;
	unsigned int count;
};

static void traffic_def_init(struct traffic_def *self)
{
	memset(self, 0, sizeof *self);
}

static void traffic_def_frame_def_add(struct traffic_def *self)
{
	struct frame_def frame_def;

	frame_def_init(&frame_def);

	ARRAY_APPEND(self->frames, &frame_def);
}

static struct frame_def *
traffic_def_frame_def_last(const struct traffic_def *self)
{
	return &self->frames[self->frames_len - 1];
}

static void traffic_def_exit(struct traffic_def *self)
{
	unsigned int i = 0;

	for (i = 0; i < self->frames_len; ++i)
		frame_def_exit(&self->frames[i]);

	ARRAY_CLEAR(self->frames);
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

struct packet {
	unsigned char packet[1514];
	struct sockaddr_ll addr;
	unsigned int len;
};

void packet_init_from_frame_def(struct packet *self, const struct frame_def *def)
{
	unsigned int i = 0;
	struct ethhdr *ethhdr = frame_def_begin((struct frame_def *)def);

	memset(self, 0, sizeof *self);

	self->addr.sll_family = AF_PACKET;
	self->addr.sll_halen = ETHER_ADDR_LEN;
	self->addr.sll_protocol = ethhdr->h_proto;

	memcpy(self->addr.sll_addr, ethhdr->h_dest, sizeof ethhdr->h_dest);

	memcpy(self->packet, def->packet, def->i);

	self->len = def->i;
}

int packet_send(const struct packet *self, int fd, int ifindex)
{
	ssize_t ret;
	struct sockaddr_ll addr = self->addr;

	addr.sll_ifindex = ifindex;

	ret = sendto(fd, self->packet, self->len, 0,
		     (const struct sockaddr *)&addr, sizeof addr);
	if (ret != self->len)
		return -1;

	return 0;
}

void packet_exit(struct packet *self)
{
	return;
}

static void generator_send(struct generator *self, const struct traffic_def *traffic_def)
{
	int ret;
	unsigned char packet[1514];
	unsigned char *ptr;
	unsigned int i;
	unsigned int j = 0;
	struct frame_def *def = &traffic_def->frames[0];
	ARRAY(struct packet, packets);

	ARRAY_CLEAR(packets);

	for (i = 0; i < traffic_def->frames_len; ++i) {
		struct packet packet;
		packet_init_from_frame_def(&packet, &traffic_def->frames[i]);
		ARRAY_APPEND(packets, &packet);
	}

	if (traffic_def->count) {
		printf("ruch: inf: sending %d frames...\n", traffic_def->count);
	} else {
		printf("ruch: inf: sending frames...\n");
	}

	while (1) {
		for (i = 0; i < packets_len; ++i) {
			struct packet *packet = &packets[i];

			ret = packet_send(packet, self->fd, traffic_def->ifindex);
			if (ret) {
				perror("ruch: err: packet_send() failed");
				break;
			}
			j++;

			if (j >= traffic_def->count)
				goto finished;
		}
	}
finished:

	for (i = 0; i < packets_len; ++i)
		packet_exit(&packets[i]);
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

int args_shiftf(struct args *self, const char *format, ...)
{
	va_list args;
	const char *arg = args_shift(self);
	int ret;
	if (!arg)
		return -1;

	va_start(args, format);
	ret = vsscanf(arg, format, args);
	va_end(args);

	return ret;
}

void args_unshift(struct args *self)
{
	self->argv--;
}

static void args_exit(struct args *self)
{
	return;
}

static int cmd_vlan(struct traffic_def *traffic_def, struct args *args)
{
	const char *arg;
	struct frame_def *def = traffic_def_frame_def_last(traffic_def);
	unsigned int tmp;
	struct vlanhdr *vlanhdr = frame_def_data(def);
	uint32_t tci = vlanhdr->tci;

	tci = ntohl(tci);

	while (1) {
		arg = args_shift(args);
		if (!arg)
			break;

		if (strcmp(arg, "id") == 0) {
			if (1 != args_shiftf(args, "%u", &tmp)) {
				fprintf(stderr, "ruch: err: invalid vid\n");
				return 1;
			}

			tci &= ~(0xFFFFFF);
			tci |= tmp & 0xFFFFFF;
			continue;
		}
		if (strcmp(arg, "pcp") == 0) {
			if (1 != args_shiftf(args, "%u", &tmp)) {
				fprintf(stderr, "ruch: err: invalid pcp\n");
				return 1;
			}

			tci &= ~(0x7 << 13);
			tci |= (tmp & 0x7) << 13;
			continue;
		}
		if (strcmp(arg, "dei") == 0) {
			if (1 != args_shiftf(args, "%u", &tmp)) {
				fprintf(stderr, "ruch: err: invalid dei\n");
				return 1;
			}

			tci &= ~(0x1 << 12);
			tci |= (tmp & 0x1) << 12;
			continue;
		}
		if (strcmp(arg, "type") == 0) {
			int type;
			int ret;

			arg = args_shift(args);
			if (!arg)
				break;

			type = ethertype_get(arg);
			if (type <= 0) {
				fprintf(stderr, "ruch: err: invalid type \"%s\"\n", arg);
				return 1;
			}

			vlanhdr->proto = htons(type);

			continue;
		}

		args_unshift(args);
		break;
	}

	vlanhdr->tci = htons(tci);

	frame_def_push(def, sizeof *vlanhdr);

	return 0;
}

static int cmd_eth(struct traffic_def *traffic_def, struct args *args)
{
	const char *arg = NULL;
	struct ether_addr ether_addr;
	struct frame_def *def = NULL;
	struct ethhdr *ethhdr = NULL;

	traffic_def_frame_def_add(traffic_def);

	def = traffic_def_frame_def_last(traffic_def);

	ethhdr = frame_def_data(def);

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

			memcpy(ethhdr->h_source, &ether_addr, sizeof ethhdr->h_source);

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

			memcpy(ethhdr->h_dest, &ether_addr, sizeof ethhdr->h_source);

			continue;
		}
		if (strcmp(arg, "type") == 0) {
			int type;
			int ret;

			arg = args_shift(args);
			if (!arg)
				break;

			type = ethertype_get(arg);
			if (type <= 0) {
				fprintf(stderr, "ruch: err: invalid type \"%s\"\n", arg);
				return 1;
			}

			ethhdr->h_proto = htons(type);

			continue;
		}
		args_unshift(args);
		break;
	}

	frame_def_push(def, sizeof *ethhdr);

	return 0;
}

static int cmd_len(struct traffic_def *traffic_def, struct args *args)
{
	unsigned int len;
	struct frame_def *def = NULL;

	def = traffic_def_frame_def_last(traffic_def);

	if (1 != args_shiftf(args, "%u", &len)) {
		fprintf(stderr, "ruch: err: invalid length\n");
		return 1;
	}

	if (len < sizeof(struct ethhdr) || 1514 < len) {
		fprintf(stderr, "ruch: err: invalid length\n");
		return 1;
	}

	frame_def_push(def, len);

	return 0;
}

static int cmd_dev(struct traffic_def *def, struct args *args)
{
	const char *arg = NULL;

	arg = args_shift(args);

	if (!arg) {
		fprintf(stderr, "ruch: err: dev requires an argument\n");
		return 1;
	}
	def->ifindex = if_nametoindex(arg);
	if (!def->ifindex) {
		perror("ruch: err: can't get ifindex");
		return 1;
	}

	return 0;
}

static int cmd_count(struct traffic_def *def, struct args *args)
{
	if (1 != args_shiftf(args, "%u", &def->count)) {
		perror("ruch: err: can't get count");
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
		.cmd = "len",
		.doit = cmd_len
	},
	{
		.cmd = "dev",
		.doit = cmd_dev
	},
	{
		.cmd = "count",
		.doit = cmd_count
	},
	{
		.cmd = "vlan",
		.doit = cmd_vlan
	},
};

int main(int argc, const char *const *argv)
{
	const char *cmd;
	unsigned int i = 0;
	struct args args;
	struct generator generator;
	struct traffic_def def = {0};
	int err;

	srand(time(NULL));

	if (argc <= 1)
		return 0;

	err = generator_init(&generator);
	if (err) {
		perror("ruch: err: generator_init() failed");
		return 1;
	}

	printf("ruch: Ruch - simple, yet effective traffic generator\n");
	printf("ruch: Version 0.1.0\n");
	printf("ruch: Copyright (C) 2020. P. Czarnota <p@czarnota.io>\n");
	printf("ruch: Licensed under GNU GPL version 2\n");
	printf("ruch: inf: generator initialized\n");

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
				if (cmds[i].doit(&def, &args)) {
					fprintf(stderr, "ruch: err: \"%s\" failed\n", cmd);
					goto err;
				}
				goto nextcmd;
			}
		}

		fprintf(stderr, "ruch: err: unknown parameter %s\n", cmd);
		goto err;
	}

	generator_send(&generator, &def);

err:
	args_exit(&args);
	traffic_def_exit(&def);
	generator_exit(&generator);

	return 0;
}
