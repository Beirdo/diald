typedef struct proxy proxy_t;

struct proxy {
	char iftype[12];
	int ifunit;
	void (*send)(proxy_t *, unsigned short, unsigned char *, size_t);
	int (*recv)(proxy_t *, unsigned char *, size_t);
	int (*init)(proxy_t *, char *);
	void (*start)(proxy_t *);
	void (*stop)(proxy_t *);
	void (*close)(proxy_t *);
	void (*release)(proxy_t *);
};

extern int proxy_init(proxy_t *proxy, char *proxydev);
extern int proxy_dev_init(proxy_t *proxy, char *proxydev);
extern int proxy_tap_init(proxy_t *proxy, char *proxydev);
extern int proxy_slip_init(proxy_t *proxy, char *proxydev);
