#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <time.h>
#include <unistd.h>

std::set<std::string> s;


int pass=0;

int is_in_set(char *host){
	std::string str(host);
	printf("host : %s\n", host);

	struct timespec start_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	int ans = s.find(str) != s.end();
	struct timespec end_time;
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	long long diff_nanoseconds = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +(end_time.tv_nsec - start_time.tv_nsec);
    double diff_milliseconds = diff_nanoseconds / 1000000.0;
	printf("find item time: %.4fms\n", diff_milliseconds);

	return ans;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
	}

	mark = nfq_get_nfmark(tb);
	ifi = nfq_get_indev(tb);
	ifi = nfq_get_outdev(tb);
	ifi = nfq_get_physindev(tb);
	ifi = nfq_get_physoutdev(tb);
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)data;
		if(ip_hdr->ip_p == IPPROTO_TCP){
			struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(data + ((ip_hdr->ip_hl)<<2));
			uint16_t dest_port = ntohs(tcp_hdr->th_dport);
			const char *host_field = "Host: ";
			const char *host_start = strstr((const char *)(data + (ip_hdr->ip_hl<<2) + (tcp_hdr->th_off << 2)), host_field);
			if(host_start){
				host_start += strlen(host_field);
				const char *host_end = strchr(host_start, '\r');
				if(host_end){
					int host_len = host_end - host_start;
					char host[host_len+1];
					strncpy(host, host_start, host_len);
					host[host_len]=0;
					if(is_in_set(host)){
						pass=0;
						return id;
					}
					else pass=1;
				}
			}
		}
	}
	pass=1;
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data){
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	if(pass==0){
		printf("filtered!!\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	char command[100];
	pid_t pid = getpid();

	sprintf(command, "top -p %d -n 1 -b > output1.txt", pid);
	//printf("%s\n", command);
	system(command);

	struct timespec start_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	std::ifstream file("top-1m.csv");
	if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string token;
            std::getline(ss, token, ',');
            std::getline(ss, token, ',');


            if (s.find(token) == s.end()) {
                s.insert(token);
            }
        }
        file.close();
    }
	struct timespec end_time;
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	long long diff_nanoseconds = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL +(end_time.tv_nsec - start_time.tv_nsec);
    double diff_milliseconds = diff_nanoseconds / 1000000.0;
	printf("File load & set input time: %.2fms\n", diff_milliseconds);

	sprintf(command, "top -p %d -n 1 -b > output2.txt", pid);
	system(command);

	FILE *file1, *file2;
	char line[256];
	file1 = fopen("output1.txt", "r");
	file2 = fopen("output2.txt", "r");
	
	printf("<<BEFORE file load & input>>\n");
	for(int i=0;i<8;i++){
		if(fgets(line, sizeof(line), file1)==NULL) break;
		if(i<6) continue;
		printf("%s", line);
	}
	printf("<<AFTER file load & input>>\n");
	for(int i=0;i<8;i++){
		if(fgets(line, sizeof(line), file2)==NULL) break;
		if(i<6) continue;
		printf("%s", line);
	}
	printf("\n");
	fclose(file1);
	fclose(file2);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}