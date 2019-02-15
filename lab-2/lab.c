#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/sched.h>
#include <asm/current.h>

int init_module(void)
{
	struct task_struct *task;
	
	for_each_process(task){
		printk(KERN_INFO "%s[%d]\n", task->comm, task->pid);
	}

	return 0;
}



void cleanup_module(void)
{
	printk(KERN_INFO "Hello: goodbye.\n");
}
