//#include <stdio.h>

struct idtr {
        unsigned short limit;
        unsigned long base;
};

struct {
        unsigned short limit;
        unsigned long base;
} __attribute__((packed)) idtr;

void draugr_idt(struct idtr *i1)
{ 
      asm("sidt %0" : "=m" (idtr));
      i1->base = idtr.base;
      i1->limit = idtr.limit;
}

/*
int main(void)
{
	struct idtr i1;

	draugr_idt(&i1);

	printf("BASE 0x%.8lx LIMIT 0x%x\n", i1.base, i1.limit);

	return 0;
}*/
