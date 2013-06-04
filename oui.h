#ifndef OUI_H
#define OUI_H

extern const char *lookup_vendor(unsigned int id);
extern void dissector_init_oui(void);
extern void dissector_cleanup_oui(void);

static inline const char *lookup_vendor_str(unsigned int id)
{
	return lookup_vendor(id) ? : "Unknown";
}

#endif /* OUI_H */
