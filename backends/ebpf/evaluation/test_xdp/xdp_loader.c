
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* DEVMAP map-value layout
 *
 * The struct data-layout of map-value is a configuration interface.
 * New members can only be added to the end of this structure.
 */
struct bpf_devmap_val {
	__u32 ifindex;   /* device index */
	union {
		int   fd;  /* prog fd on map write */
		__u32 id;  /* prog id on map read */
	} bpf_prog;
};

/* 
 * extract map from the xdp prog and pinned 
 * it to control it from bpftool map
 * TODO: pin to /sys/fs/bpf/xdp/globals/ingress_tbl_fwd ???
 */
static const char *pinned_ingress_tbl_fwd_file = "/sys/fs/bpf/ingress_tbl_fwd";

static int ifindex_in;
static int ifindex_out;

static bool ifindex_out_xdp_dummy_attached = true;
static bool xdp_egress_prog_attached = true;

static __u32 prog_id;
static __u32 dummy_prog_id;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static void int_exit(int sig) {
	__u32 curr_prog_id = 0;

	if(bpf_get_link_xdp_id(ifindex_in, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id(1) failed.\n");
		exit(1);
	}

	if(prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex_in, -1, xdp_flags);
	else if(!curr_prog_id)
		printf("couldn't find a prog id on *ingress* iface.\n");
	else
		printf("prog on *ingress* iface changed, not removing.\n");

	if(ifindex_out_xdp_dummy_attached) {
		curr_prog_id = 0;

		if(bpf_get_link_xdp_id(ifindex_out, &curr_prog_id, xdp_flags)) {
			printf("bpf_get_link_xdp_id(2) failed.\n");
			exit(1);
		}

		if(dummy_prog_id == curr_prog_id)
			bpf_set_link_xdp_fd(ifindex_out, -1, xdp_flags);
		else if(!curr_prog_id)
			printf("couldn't find a prog id on *egress* iface.\n");
		else
			printf("prog on *egress* iface changed, not removing.\n");
	}

	exit(0);
}

int main(int argc, char **argv) {
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_UNSPEC,
	};

	struct bpf_object *obj;
	char filename[256];

	struct bpf_program *prog, *dummy_prog, *egress_prog;
	int prog_fd, dummy_prog_fd, egress_prog_fd = -1;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	int tx_port_map_fd, ingress_tbl_fwd_fd;
	struct bpf_devmap_val devmap_val;

	int ret = 0, index = 0;

	xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;

	if(!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;
	else if(xdp_egress_prog_attached) {
		printf("load xdp prog on egress in SKB mode not supported yet.\n");
		return 1;
	}

	/* get egress and ingress interfaces */
	ifindex_in = if_nametoindex(argv[2]);
	if(!ifindex_in)
		ifindex_in = strtoul(argv[2], NULL, 0);

	ifindex_out = if_nametoindex(argv[3]);
	if(!ifindex_out)
		ifindex_out = strtoul(argv[3], NULL, 0);

	printf("input = %d, output = %d.\n", ifindex_in, ifindex_out);

	/* get .kern prog file */
	snprintf(filename, sizeof(filename), "%s", argv[1]);
	prog_load_attr.file = filename;

	if(bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("bpf_prog_load_xattr(1) failed.\n");
		return 1;
	}

	/* load the ingress_tbl_fwd and pinned it */
	ingress_tbl_fwd_fd = bpf_object__find_map_fd_by_name(obj, "ingress_tbl_fwd");
	if(ingress_tbl_fwd_fd < 0) {
		printf("finding ingress_tbl_fwd in obj file failed.\n");
		goto out;
	}

	ret = bpf_obj_pin(ingress_tbl_fwd_fd, pinned_ingress_tbl_fwd_file);
	if(ret) {
		printf("failed to pinned ingress_tbl_fwd. err=%s\n", strerror(errno));
	}

	/* Load ingress and dummy sections */
	prog = bpf_object__find_program_by_name(obj, "xdp_ingress_func");
	if(!prog) {
		printf("finding ingress prog in obj file failed.\n");
		goto out;
	}
	dummy_prog = bpf_object__find_program_by_name(obj, "xdp_redirect_dummy");
	if(dummy_prog < 0) {
		printf("finding dummy_prog in obj file failed.\n");
		goto out;
	}
	prog_fd = bpf_program__fd(prog);
	dummy_prog_fd = bpf_program__fd(dummy_prog);
	if(prog_fd < 0 || dummy_prog_fd < 0) {
		printf("bpf_prog_load_xattr: %s.\n", strerror(errno));
		return 1;
	}

	/* Load the devmap */
	tx_port_map_fd = bpf_object__find_map_fd_by_name(obj, "tx_port");
	if(tx_port_map_fd < 0) {
		printf("finding tx_port_map in obj file failed.\n");
		goto out;
	}

	/* Attach the ingress prog */
	if(bpf_set_link_xdp_fd(ifindex_in, prog_fd, xdp_flags) < 0) {
		printf("ERROR: bpf_set_link_xdp_fd(1) failed on iface %d.\n", ifindex_in);
		return 1;
	}

	ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if(ret) {
		printf("couldn't get prog info - %s.\n", strerror(errno));
		return ret;
	}
	prog_id = info.id;

	/* attach dummy prog out-device */
	if(bpf_set_link_xdp_fd(ifindex_out, dummy_prog_fd, 
				(xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST)) < 0) {
		printf("WARN: bpf_set_link_xdp_fd(2) failed on, iface %d.\n", ifindex_out);
		ifindex_out_xdp_dummy_attached = false;
	}

	memset(&info, 0, sizeof(info));
	ret = bpf_obj_get_info_by_fd(dummy_prog_fd, &info, &info_len);
	if(ret) {
		printf("couldn't get prog info - %s.\n", strerror(errno));
		return ret;
	}
	dummy_prog_id = info.id;

	if(xdp_egress_prog_attached) { // For now, always true
		egress_prog = bpf_object__find_program_by_name(obj, "xdp_egress_func");
		if(!egress_prog) {
			printf("finding egress_prog in obj file failed.\n");
			goto out;
		}
		egress_prog_fd = bpf_program__fd(egress_prog);
		if(egress_prog_fd < 0) {
			printf("finding egress_prog_fd failed.\n");
			goto out;
		}
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	devmap_val.ifindex = ifindex_out;
	devmap_val.bpf_prog.fd = egress_prog_fd;
	ret = bpf_map_update_elem(tx_port_map_fd, &index, &devmap_val, 0);
	if(ret) {
		perror("bpf_map_update_elem tx_port_map_fd");
		goto out;
	}

out:
	return 0;
}