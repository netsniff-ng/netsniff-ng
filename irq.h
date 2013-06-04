#ifndef IRQ_H
#define IRQ_H

extern int device_irq_number(const char *ifname);
extern void device_restore_irq_affinity_list(void);
extern int device_set_irq_affinity_list(int irq, unsigned long from,
					unsigned long to);
extern int device_set_irq_affinity(int irq, unsigned long cpu);

#endif /* IRQ_H */
