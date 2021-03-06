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
#include <linux/udp.h>
#include <endian.h>

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

static int streqi(const char *a, const char *b)
{
	unsigned int i = 0;

	if (strlen(a) != strlen(b))
		return 0;

	for (i = 0; i < strlen(a); ++i)
		if (tolower(a[i]) != tolower(b[i]))
			return 0;

	return 1;
}

#define IP_PROTO(x) { #x, IPPROTO_##x }
static const struct {
	const char *name;
	uint16_t value;
} protocols[] = {
    IP_PROTO(IP),
    IP_PROTO(ICMP),
    IP_PROTO(IGMP),
    IP_PROTO(IPIP),
    IP_PROTO(TCP),
    IP_PROTO(EGP),
    IP_PROTO(PUP),
    IP_PROTO(UDP),
    IP_PROTO(IDP),
    IP_PROTO(TP),
    IP_PROTO(DCCP),
    IP_PROTO(IPV6),
    IP_PROTO(RSVP),
    IP_PROTO(GRE),
    IP_PROTO(ESP),
    IP_PROTO(AH),
    IP_PROTO(MTP),
    IP_PROTO(BEETPH),
    IP_PROTO(ENCAP),
    IP_PROTO(PIM),
    IP_PROTO(COMP),
    IP_PROTO(SCTP),
    IP_PROTO(UDPLITE),
    IP_PROTO(MPLS),
    IP_PROTO(RAW),
};
static int ipproto_get(const char *protocol)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(protocols); ++i)
		if (streqi(protocols[i].name, protocol))
                  return protocols[i].value;

        return -1;
}

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
static int ethertype_get(const char *ethertype)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(ethertypes); ++i)
		if (streqi(ethertypes[i].name, ethertype))
                  return ethertypes[i].value;

        return -1;
}

static void random_mac_addr(unsigned char *octet)
{
	unsigned int i = 0;

	octet[0] = 0xD8;
	octet[1] = 0xCB;
	octet[2] = 0x8A;

	for (i = 3; i < ETHER_ADDR_LEN; ++i)
		octet[i] = rand() % 250 + 10;
}

struct frame_filler {
	void *p;
	const unsigned int offset;
	const unsigned int size;
	void (*fill)(struct frame_filler *self, void *packet);
	void (*destroy)(struct frame_filler *self);
};

struct frame_def {
	unsigned char packet[1600];
	unsigned int i;
	ARRAY(struct frame_filler, fillers);
	unsigned int times;
};

static unsigned int frame_def_remaining(struct frame_def *self)
{
	return ARRAY_SIZE(self->packet) - self->i;
}

static void *frame_def_data(struct frame_def *self)
{
	return &self->packet[self->i];
}

static void *frame_def_begin(struct frame_def *self)
{
	return &self->packet[0];
}

static void *frame_def_offset(struct frame_def *self, unsigned int offset)
{
	return self->packet + offset;
}

static void frame_def_init(struct frame_def *self)
{
	struct ethhdr *ethhdr;

	memset(self, 0, sizeof *self);

	ethhdr = frame_def_data(self);

	random_mac_addr(ethhdr->h_dest);
	random_mac_addr(ethhdr->h_source);

	ethhdr->h_proto = htons(ETH_P_IP);

	self->times = 1;
}

static void frame_def_push(struct frame_def *self, unsigned int size)
{
	self->i += size;
}

static void frame_def_pop(struct frame_def *self, unsigned int size)
{
	self->i -= size;
}

static unsigned int frame_def_size(const struct frame_def *self)
{
	return self->i;
}

static void frame_def_filler_push(struct frame_def *self,
				  struct frame_filler *filler)
{
	ARRAY_APPEND(self->fillers, filler);
	frame_def_push(self, filler->size);
}

static void frame_def_exit(struct frame_def *self)
{
	unsigned int i;

	for (i = 0; i < self->fillers_len; ++i)
		if (self->fillers[i].destroy)
			self->fillers[i].destroy(&self->fillers[i]);

	ARRAY_CLEAR(self->fillers);
}

struct traffic_def {
	ARRAY(struct frame_def, frames);
	int ifindex;
#define COUNT_FOREVER -1
#define COUNT_EXACT -2
	int count;
	unsigned int rate;
#define BURST_ALL_RATE 0
	int burst;
};

static void traffic_def_init(struct traffic_def *self)
{
	memset(self, 0, sizeof *self);
	self->burst = 1;
	self->count = COUNT_EXACT;
}

static void traffic_def_frame_def_add(struct traffic_def *self)
{
	struct frame_def frame_def;

	frame_def_init(&frame_def);

	ARRAY_APPEND(self->frames, &frame_def);
}

static int traffic_def_count_get(const struct traffic_def *self)
{
	int count = 0;
	unsigned int i = 0;

	if (self->count == COUNT_FOREVER)
		return COUNT_FOREVER;

	if (self->count >= 0)
		return self->count;

	for (i = 0; i < self->frames_len; ++i)
		count += self->frames[i].times;

	return count;
}

static unsigned int traffic_def_size_in_bytes(const struct traffic_def *self)
{
	unsigned int size = 0;
	unsigned int i = 0;
	int count = traffic_def_count_get(self);

	if (!self->frames_len)
		return 0;

	if (count <= 0)
		return 0;

	for (i = 0; i < self->frames_len; ++i)
		size += frame_def_size(&self->frames[i]);

	size *= count / self->frames_len;

	for (i = 0; i < count % self->frames_len; ++i)
		size += frame_def_size(&self->frames[i]);

	return size;
}

static struct frame_def *
traffic_def_frame_def_last(const struct traffic_def *self)
{
	if (self->frames_len <= 0)
		return NULL;

	return &self->frames[self->frames_len - 1];
}

static void traffic_def_exit(struct traffic_def *self)
{
	unsigned int i = 0;

	for (i = 0; i < self->frames_len; ++i)
		frame_def_exit(&self->frames[i]);

	ARRAY_CLEAR(self->frames);
}

struct packet {
	unsigned char packet[1514];
	struct sockaddr_ll addr;
	unsigned int len;
};

void packet_from_frame_def(struct packet *self, struct frame_def *def)
{
	unsigned int i = 0;
	struct ethhdr *ethhdr = frame_def_begin((struct frame_def *)def);

	memset(self, 0, sizeof *self);

	self->addr.sll_family = AF_PACKET;
	self->addr.sll_halen = ETHER_ADDR_LEN;
	self->addr.sll_protocol = ethhdr->h_proto;

	memcpy(self->addr.sll_addr, ethhdr->h_dest, sizeof ethhdr->h_dest);

	memcpy(self->packet, def->packet, def->i);

	for (i = 0; i < def->fillers_len; ++i) {
		struct frame_filler *filler = &def->fillers[i];

		if (!filler->fill)
			continue;

		filler->fill(filler, &self->packet[filler->offset]);
	}

	self->len = def->i;
}

void packet_into_frame_def(const struct packet *self, struct frame_def *def)
{
	memcpy(def->packet, self->packet, self->len);
	def->i = self->len;
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
}

struct generator {
	int fd;
	int send_called;
};

static int generator_init(struct generator *self)
{
	memset(self, 0, sizeof *self);

	self->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (self->fd < 0)
		return -1;

	return 0;
}

static double time_since(double *time)
{
	double old = *time;
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t);

	*time = (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0f;

	return *time - old;
}

static void time_wait(double time)
{
	struct timespec t;

	if (time <= 0.0f)
		return;

	t.tv_sec = (time_t)time;
	t.tv_nsec = (time - (unsigned long)time) * 1000000000;

	if (nanosleep(&t, NULL))
		perror("ruch: err: nanosleep() failed");
}

static void generator_send(struct generator *self, const struct traffic_def *traffic_def)
{
	int ret;
	unsigned int i;
	unsigned int j = 0;
	unsigned int k = 0;
	unsigned int size = 0;
	double dt = 0.0f;
	double throughput;
	double delta;
	double time_to_wait = 0.0f;
	double packet_time = 0.0f;
	int burst_data_count = 0;
	int burst_packets_count = 0;
	int count = traffic_def_count_get(traffic_def);

	if (count >= 0) {
		printf("ruch: inf: sending %d frames (%d bytes)...\n",
		       count,
		       traffic_def_size_in_bytes(traffic_def));
	} else {
		printf("ruch: inf: sending frames...\n");
	}

	time_since(&dt);

	if (count == 0)
		goto finished;

	time_since(&packet_time);

	while (1) {
		for (i = 0; i < traffic_def->frames_len; ++i) {
			struct frame_def *def = &traffic_def->frames[i];

			for (k = 0; k < def->times; ++k) {
				struct packet packet;

				packet_from_frame_def(&packet, def);

				ret = packet_send(&packet, self->fd, traffic_def->ifindex);
				if (ret) {
					perror("ruch: err: packet_send() failed");
					break;
				}
				j++;

				burst_data_count += packet.len;
				burst_packets_count += 1;

				/* Burst only works now when rate is specified */
				if (traffic_def->rate) {
					int rate_exceeded = burst_data_count * 8 > traffic_def->rate;
					int packets_exceeded = burst_packets_count == traffic_def->burst;
					int packet_limited_burst = traffic_def->burst > 0;

					if (packet_limited_burst && packets_exceeded || rate_exceeded) {
						/* Wait to achieve the specified throughput */
						time_to_wait += (double)burst_data_count / (traffic_def->rate / 8) - time_since(&packet_time);
						time_wait(time_to_wait);
						time_to_wait -= time_since(&packet_time);
						burst_data_count = 0;
						burst_packets_count = 0;
					}
				}

				size += packet.len;

				packet_exit(&packet);

				if (count >= 0 && j >= count)
					goto finished;
			}
		}
	}

	self->send_called = 1;
finished:
	delta = time_since(&dt);
	if (delta) {
		throughput = ((double)size / delta) * 8;
		printf("ruch: inf: achieved data rate of %f Mbps\n", throughput / 1024.0f / 1024.0f);
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

			memcpy(ethhdr->h_dest, &ether_addr, sizeof ethhdr->h_dest);

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

	if (len < frame_def_size(def)) {
		fprintf(stderr, "ruch: err: specified len is smaller that actual packet size\n");
		return 1;
	}

	frame_def_push(def, len - frame_def_size(def));

	return 0;
}

static int cmd_zeros(struct traffic_def *traffic_def, struct args *args)
{
	unsigned int len;
	struct frame_def *def = NULL;

	def = traffic_def_frame_def_last(traffic_def);

	if (1 != args_shiftf(args, "%u", &len)) {
		fprintf(stderr, "ruch: err: invalid length\n");
		return 1;
	}

	/* TODO: Overflow!!! */
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

static int cmd_forever(struct traffic_def *def, struct args *args)
{
	def->count = COUNT_FOREVER;
	return 0;
}

static int cmd_send(struct traffic_def *def, struct args *args)
{
	return 0;
}

static int cmd_ip(struct traffic_def *traffic_def, struct args *args)
{
	const char *arg = NULL;
	struct frame_def *def = NULL;
	struct iphdr *iphdr = NULL;

	def = traffic_def_frame_def_last(traffic_def);

	iphdr = frame_def_data(def);

	iphdr->ihl = 5;
	iphdr->version = 4;
	iphdr->tos = 0;
	iphdr->tot_len = 0;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 64;
	iphdr->check = 0;
	iphdr->protocol = 0;

	inet_pton(AF_INET, "10.0.0.1", &iphdr->saddr);
	inet_pton(AF_INET, "20.0.0.1", &iphdr->daddr);

	while (1) {
		arg = args_shift(args);
		if (!arg)
			break;

		if (strcmp(arg, "tot_len") == 0) {
			uint16_t tot_len;
			if (1 != args_shiftf(args, "%hu", &tot_len)) {
				fprintf(stderr, "ruch: err: ip: len requires an argument\n");
				return 1;
			}
			iphdr->tot_len = htons(tot_len);

			continue;
		}

		if (strcmp(arg, "s") == 0) {
			arg = args_shift(args);
			if (!arg)
				break;

			inet_pton(AF_INET, arg, &iphdr->saddr);
			continue;
		}

		if (strcmp(arg, "d") == 0) {
			arg = args_shift(args);
			if (!arg)
				break;

			inet_pton(AF_INET, arg, &iphdr->daddr);
			continue;
		}

		if (strcmp(arg, "proto") == 0) {
			int proto;
			int ret;

			arg = args_shift(args);
			if (!arg)
				break;

			proto = ipproto_get(arg);
			if (proto <= 0) {
				fprintf(stderr, "ruch: err: ip: invalid proto \"%s\"\n", arg);
				return 1;
			}

			iphdr->protocol = proto;

			continue;
		}

		args_unshift(args);
		break;
	}

	frame_def_push(def, sizeof *iphdr);

	return 0;
}

static int cmd_udp(struct traffic_def *traffic_def, struct args *args)
{
	const char *arg = NULL;
	struct frame_def *def = NULL;
	struct udphdr *udphdr = NULL;

	def = traffic_def_frame_def_last(traffic_def);

	udphdr = frame_def_data(def);

	udphdr->source = htons(7001);
	udphdr->dest = htons(8001);
	udphdr->len = 0;
	udphdr->check = 0;

	while (1) {
		arg = args_shift(args);
		if (!arg)
			break;

		if (strcmp(arg, "s") == 0) {
			uint16_t s;
			if (1 != args_shiftf(args, "%hu", &s)) {
				fprintf(stderr, "ruch: err: udp: s requires an argument\n");
				return 1;
			}
			udphdr->source = htons(s);

			continue;
		}
		if (strcmp(arg, "d") == 0) {
			uint16_t d;
			if (1 != args_shiftf(args, "%hu", &d)) {
				fprintf(stderr, "ruch: err: udp: d requires an argument\n");
				return 1;
			}
			udphdr->dest = htons(d);

			continue;
		}

		args_unshift(args);
		break;
	}

	frame_def_push(def, sizeof *udphdr);

	return 0;
}

static uint64_t timestamp(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);

	return (uint64_t)(t.tv_sec) * (uint64_t)1000000000 + (uint64_t)(t.tv_nsec);
}
static void timestamp_filler_fill(struct frame_filler *self, void *packet)
{
	uint64_t *t = packet;

	*t = htobe64(timestamp());
}

static int cmd_timestamp(struct traffic_def *traffic_def, struct args *args)
{
	struct frame_def *def = traffic_def_frame_def_last(traffic_def);
	struct frame_filler timestamp_filler = {
		.offset = frame_def_size(def),
		.size = sizeof(uint64_t),
		.fill = timestamp_filler_fill
	};

	frame_def_filler_push(def, &timestamp_filler);

	return 0;
}

static int cmd_rate(struct traffic_def *def, struct args *args)
{
	if (1 != args_shiftf(args, "%u", &def->rate)) {
		perror("ruch: err: can't get rate");
		return 1;
	}

	return 0;
}

static int cmd_burst(struct traffic_def *def, struct args *args)
{
	int ret = args_shiftf(args, "%u", &def->burst);

	if (ret < 0) {
		def->burst = BURST_ALL_RATE;
		return 0;
	}

	if (ret != 1) {
		/* The burst command was passed without an argument */
		def->burst = BURST_ALL_RATE;
		args_unshift(args);
	}
	return 0;
}

static int cmd_times(struct traffic_def *traffic_def, struct args *args)
{
	struct frame_def *def = traffic_def_frame_def_last(traffic_def);

	if (!def) {
		fprintf(stderr, "ruch: err: you need a stream");
		return 1;
	}

	if (1 != args_shiftf(args, "%u", &def->times)) {
		perror("ruch: err: can't get times");
		return 1;
	}

	return 0;
}

static int
xsnprintf(char *data, unsigned int size, const char *format, ...)
{
	va_list args, args2;
	int ret;
	char one;

	va_start(args, format);
	va_copy(args2, args);

	ret = vsnprintf(&one, 1, format, args);
	va_end(args);

	if (ret + 1 > size)
		goto finish;

	ret = vsnprintf(data, size, format, args2);

finish:
	va_end(args2);

	return ret;
}

static int cmd_str(struct traffic_def *traffic_def, struct args *args)
{
	struct frame_def *def = NULL;
	const char *str;
	int len;

	def = traffic_def_frame_def_last(traffic_def);

	str = args_shift(args);
	if (!str) {
		fprintf(stderr, "ruch: err: expected string\n");
		return 1;
	}

	len = xsnprintf(frame_def_data(def), frame_def_remaining(def), "%s", str);
	if (len >= frame_def_remaining(def)) {
		fprintf(stderr, "ruch: err: string too big\n");
		return 1;
	}

	frame_def_push(def, len + 1);

	return 0;
}

static const struct {
	const char *cmd;
	int (*doit)(struct traffic_def *def, struct args *args);
	const char *summary;
} cmds[] = {
	{
		.cmd = "eth",
		.summary = "inserts Ethernet II header",
		.doit = cmd_eth,
	},
	{
		.cmd = "vlan",
		.summary = "inserts VLAN header",
		.doit = cmd_vlan,
	},
	{
		.cmd = "ip",
		.summary = "inserts IP header",
		.doit = cmd_ip,
	},
	{
		.cmd = "udp",
		.summary = "inserts UDP header",
		.doit = cmd_udp,
	},
	{
		.cmd = "zeros",
		.summary = "inserts specified number of zeros",
		.doit = cmd_zeros,
	},
	{
		.cmd = "len",
		.summary = "inserts zeros to reach specific frame length",
		.doit = cmd_len,
	},
	{
		.cmd = "timestamp",
		.summary = "inserts a current timestamp",
		.doit = cmd_timestamp,
	},
	{
		.cmd = "str",
		.summary = "inserts NULL terminated string into the frame",
		.doit = cmd_str,
	},
	{
		.cmd = "dev",
		.summary = "send frames through device",
		.doit = cmd_dev,
	},
	{
		.cmd = "count",
		.summary = "limit number of packets that the generator will send in total",
		.doit = cmd_count,
	},
	{
		.cmd = "send",
		.summary = "",
		.doit = cmd_send,
	},
	{
		.cmd = "rate",
		.summary = "send packets at specified rate",
		.doit = cmd_rate,
	},
	{
		.cmd = "burst",
		.summary = "specifies how many packets generator will be sending at once",
		.doit = cmd_burst,
	},
	{
		.cmd = "times",
		.summary = "repeats the current frame definition N times",
		.doit = cmd_times,
	},
	{
		.cmd = "forever",
		.summary = "generate traffic until ruch is terminated",
		.doit = cmd_forever,
	},
};

static void print_help(void)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(cmds); ++i)
		printf("    %-10s %s\n", cmds[i].cmd, cmds[i].summary);
}

/* Calculate correct packets lengths after packet is prepared */
static int process_len(struct frame_def *def)
{
	unsigned int offset = 0;
	struct ethhdr *ethhdr = frame_def_offset(def, offset);
	uint16_t eth_proto;
	struct iphdr *iphdr;
	struct udphdr *udphdr;

	ethhdr = frame_def_offset(def, offset);

	eth_proto = ethhdr->h_proto;
	offset += sizeof *ethhdr;

	while (eth_proto == htons(ETH_P_8021Q) ||
	       eth_proto == htons(ETH_P_8021AD)) {
		struct vlanhdr *vlanhdr = frame_def_offset(def, offset);

		eth_proto = vlanhdr->proto;
		offset += sizeof *vlanhdr;
	}

	/* At this moment eth_proto is not vlan */

	if (eth_proto != htons(ETH_P_IP))
		return 0;

	iphdr = frame_def_offset(def, offset);
	iphdr->tot_len = htons((unsigned char *)frame_def_data(def) -
		(unsigned char *)iphdr);

	offset += sizeof *iphdr;

	if (iphdr->protocol != IPPROTO_UDP)
		return 0;

	udphdr = frame_def_offset(def, offset);
	udphdr->len = htons((unsigned char *)frame_def_data(def) -
		(unsigned char *)udphdr);

	return 0;
}

static unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

static int process_csum(struct frame_def *def)
{
	unsigned int offset = 0;
	struct ethhdr *ethhdr;
	uint16_t eth_proto;
	struct iphdr *iphdr;
	struct udphdr *udphdr;

	ethhdr = frame_def_offset(def, offset);

	eth_proto = ethhdr->h_proto;
	offset += sizeof *ethhdr;

	while (eth_proto == htons(ETH_P_8021Q) ||
	       eth_proto == htons(ETH_P_8021AD)) {
		struct vlanhdr *vlanhdr = frame_def_offset(def, offset);

		eth_proto = vlanhdr->proto;
		offset += sizeof *vlanhdr;
	}

	/* At this moment eth_proto is not vlan */

	if (eth_proto != htons(ETH_P_IP))
		return 0;

	iphdr = frame_def_offset(def, offset);

	if (iphdr->protocol != IPPROTO_UDP)
		return 0;

	iphdr->check = csum((unsigned short *)iphdr, sizeof(struct iphdr) >> 1);

	offset += sizeof *iphdr;
	udphdr = frame_def_offset(def, offset);
	/* TODO: Calculate UDP checksum */
	udphdr->check = 0;

	return 0;
}

int (*const frame_processors[])(struct frame_def *def) = {
	process_len,
	process_csum
};

void print_usage(void)
{
	printf("ruch - simple, yet effective traffic generator\n");
	printf("Version 0.1.0\n");
	printf("Copyright (C) 2020 by P. Czarnota <p@czarnota.io>\n");
	printf("Licensed under GNU GPL version 3\n");
	printf("\n");
	printf("Usage:\n");
	printf("\n");
	printf("    ruch COMMANDS");
	printf("\n");
	printf("\n");
	printf("COMMANDS is one of:\n");
	printf("\n");
	print_help();
	printf("\n");
}

int main(int argc, const char *const *argv)
{
	const char *cmd;
	unsigned int i = 0;
	unsigned int j = 0;
	struct args args;
	struct generator generator;
	struct traffic_def def = {0};
	int err;

	srand(time(NULL));

	if (argc <= 1) {
		print_usage();
		return 0;
	}

	err = generator_init(&generator);
	if (err) {
		perror("ruch: err: generator_init() failed");
		return 1;
	}

	printf("ruch: Ruch - simple, yet effective traffic generator\n");
	printf("ruch: Version 0.1.0\n");
	printf("ruch: Copyright (C) 2020 by P. Czarnota <p@czarnota.io>\n");
	printf("ruch: Licensed under GNU GPL version 3\n");
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

	for (i = 0; i < def.frames_len; ++i) {
		for (j = 0; j < ARRAY_SIZE(frame_processors); ++j) {
			if (frame_processors[j](&def.frames[i])) {
				fprintf(stderr, "ruch: err: frame processing failed\n");
				goto err;
			}
		}
	}

	generator_send(&generator, &def);
err:
	args_exit(&args);
	traffic_def_exit(&def);
	generator_exit(&generator);

	return 0;
}
