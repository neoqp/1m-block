all: netfilter-test

netfilter-test:
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	gcc -o netfilter-test main.c -lnetfilter_queue

clean:
	rm -f netfilter-test
	rm -f index*