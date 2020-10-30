#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF_SIZE 500

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct header {
	unsigned short identification;		// These 2 bytes are randomly generated
	unsigned short flags;				// This can be hardcoded, not important: 00 01
	unsigned short questions; 			// This is the number of questions in the wire
	unsigned short answerResourceRecords;
	unsigned short authorityAdditionalResourceRecords1;	// This will always be: 00 00 00 00
	unsigned short authorityAdditionalResourceRecords2;
}dns_query_header; // dns_query_header is a variable and you can start using right away

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
}

int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}


unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */
	struct header dnsHeader;
	struct header *ptr_dnsHeader;
	ptr_dnsHeader = &dnsHeader;
	ptr_dnsHeader->identification = 0x0404; // ptr_dnsHeader->identification = 0xD627;
	ptr_dnsHeader->flags = 0x0001;
	ptr_dnsHeader->questions = 0x0100;
	ptr_dnsHeader->answerResourceRecords = 0x0000;
	ptr_dnsHeader->authorityAdditionalResourceRecords1 = 0x0000;
	ptr_dnsHeader->authorityAdditionalResourceRecords2 = 0x0000;

	memcpy(wire, (unsigned char*)ptr_dnsHeader, sizeof(dnsHeader)); // sizeof(dns_query_header)
	int sizeOfWire = (sizeof(dnsHeader) / sizeof(char)) - 1;

	char* token = strtok(qname, ".");
	int byteoffset = sizeOfWire + 1;
	while (token != NULL) {
    	wire[byteoffset] = strlen(token);
    	byteoffset += 1;
    	for (int i = 0; i < strlen(token); i++) {
       		wire[byteoffset] = token[i];
        	byteoffset += 1;
    	}
    	token = strtok(NULL, ".");
    	// printf("offest: %d\n", byteoffset);
	}
	wire[byteoffset] = 0x00;	// null label of question
	byteoffset += 1;

	// Type 1 = IPv4 address, Class 1 = IN, Internet (These can be hardcoded): 00 01 00 01
	wire[byteoffset] = 0x00;
	byteoffset +=1;
	wire[byteoffset] = 0x01;
	byteoffset +=1;
	wire[byteoffset] = 0x00;
	byteoffset +=1;
	wire[byteoffset] = 0x01;
	byteoffset += 1;
	// print_bytes(wire, byteoffset);

	return (byteoffset);
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */


	int numanswers = wire[7];
	struct dns_answer_entry* head = malloc(sizeof(dns_answer_entry));
	struct dns_answer_entry** curr = &head;
	int byteoffset = 0x0c; //position of first domain name


	int skipSize = 1;
	while (skipSize != 0)
	{
		int sizeToSkip = wire[byteoffset];
		byteoffset+= wire[byteoffset];
		byteoffset+=1;
		skipSize = sizeToSkip;
	}

	byteoffset += 16;

   	for (int i = 0; i < numanswers; i++){
       	char* ip = malloc(16);
	   	sprintf(ip, "%d.%d.%d.%d", wire[byteoffset], wire[byteoffset + 1], wire[byteoffset + 2], wire[byteoffset+ 3]); 
       	printf("%s\n", ip);
		byteoffset += 16; // 16
		// LINKED LIST
		// dns_answer_entry* old = *curr;
      	// old->value = ip;
       	// dns_answer_entry* new = malloc(sizeof(struct dns_answer_entry));
       	// old->next = new;
       	// curr = &new;
	   	// if(i + 1 == numanswers) {
		//    old->next = NULL;
	   	// }
	}

//    return head;
   return NULL;
}

// USE THIS!!!
int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, char* port) {
    /*
     * Send a message (request) over UDP to a server (server) and port
     * (port) and wait for a response, which is placed in another byte
     * array (response).  Create a socket, "connect()" it to the
     * appropriate destination, and then use send() and recv();
     *
     * INPUT:  request: a pointer to an array of bytes that should be sent
     * INPUT:  requestlen: the length of request, in bytes.
     * INPUT:  response: a pointer to an array of bytes in which the
     *             response should be received
     * OUTPUT: the size (bytes) of the response received
     */
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    size_t len;
    ssize_t nread;

    /* Obtain address(es) matching host/port */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */
    s = getaddrinfo(server, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    }
    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol);
        if (sfd == -1)
            continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */
        close(sfd);
    }
    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);           /* No longer needed */
    
    if (write(sfd, request, requestlen) != requestlen) {
        fprintf(stderr, "partial/failed write\n");
        exit(EXIT_FAILURE);
    }
	
    nread = read(sfd, response, BUF_SIZE);
    if (nread == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    return nread;
}

dns_answer_entry *resolve(char *qname, char *server, char *port) {
    unsigned char *wire;
    wire = (char*) malloc(256 * sizeof(char));
    dns_rr_type type = 1;
    unsigned short lengthOfWire = create_dns_query(qname, type, wire);
	// print_bytes(wire, lengthOfWire); // This prints the wire
    char response[BUF_SIZE];
    int responseLength = send_recv_message(wire, lengthOfWire, response, server, port);
    struct dns_answer_entry* list = get_answer_address(qname, type, response);
	// print_bytes(response, responseLength); // This prints the response

    return list;
}

int main(int argc, char *argv[]) {
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL) {
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}
