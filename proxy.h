struct proxy {
	char *iftype;
	int ifunit;
	void (*send)(unsigned short, unsigned char *, size_t);
	int (*recv)(unsigned char *, size_t);
	int (*init)(char *);
	void (*start)(void);
	void (*stop)(void);
	void (*close)(void);
	void (*release)(void);
};

extern struct proxy *proxy;

extern struct proxy proxy_dev;
extern struct proxy proxy_tap;
extern struct proxy proxy_slip;


extern int proxy_init(char *proxydev);
