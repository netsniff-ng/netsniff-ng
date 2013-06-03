#ifndef IRQ_H
#define IRQ_H

extern int device_irq_number(const char *ifname);
extern int device_bind_irq_to_cpu(int irq, int cpu);
extern void device_restore_irq_affinity_list(void);
extern int device_set_irq_affinity_list(int irq, unsigned long from,
					unsigned long to);

#endif /* IRQ_H */
