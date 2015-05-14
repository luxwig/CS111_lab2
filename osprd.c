#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Jing");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);


struct pid_list
{
	pid_t pid;
	struct pid_list*next;
};
typedef struct pid_list* pid_list_t;

struct ticket_list
{
	int num;
	struct ticket_list*next;
};
typedef struct ticket_list* ticket_list_t;

/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */
	int read_locks;
	int write_locks;
	pid_list_t read_queue;
	pid_t write_pid;
	ticket_list_t ticket_queue;
	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions

//check if the current pid exsits in the given list
int check_pid(pid_t a, pid_list_t b)
{
	pid_list_t curr = b;
	while (curr != NULL)
	{
		if (curr->pid == a)
			return 1;
		curr = curr->next;
	}
	return 0;
}

//check if the ticket number exsits in the list
int check_ticket(int a, ticket_list_t b)
{
	ticket_list_t curr = b;
        while (curr != NULL)
        {
                if (curr->num == a)
                        return 1;
                curr = curr->next;
        }
        return 0;

}

//add the pid to the list
void add_pid(pid_t a, pid_list_t d)
	{
		if (d == NULL)
		{
			d = kzalloc(sizeof(pid_list_t), GFP_ATOMIC);
			d->pid = a;
			d->next = NULL;
		}
		else
		{
			while (d != NULL)
			{
				d = d->next;
			}
			d = kzalloc(sizeof(pid_list_t), GFP_ATOMIC);
			d->pid = a;
			d->next = NULL;
		}
	}
//add the ticket to the list
void add_ticket(int a, ticket_list_t d)
{
               if (d == NULL)
                {
                        d = kzalloc(sizeof(ticket_list_t), GFP_ATOMIC);
                        d->num = a;
                        d->next = NULL;
                }
                else
                {
                        while (d != NULL)
                        {
                                d = d->next;
                        }
                        d = kzalloc(sizeof(ticket_list_t), GFP_ATOMIC);
                        d->num = a;
                        d->next = NULL;
                }

}

//release the readlock
void remove_pid(pid_t t, pid_list_t d)
{
	pid_list_t prev = d;
	pid_list_t curr = d;
	while (curr != NULL)
	{
		if (curr->pid == t)
		{
			if (curr == d)
				d = NULL;
			else prev->next = curr->next;
			break;
		}
		else
		{
			prev = curr;
			curr = curr->next;
		}
	}

}

//remove the ticket
void remove_ticket(int t, ticket_list_t d)
{
        ticket_list_t prev = d;
        ticket_list_t curr = d;
        while (curr != NULL)
        {
                if (curr->num == t)
                {
                        if (curr == d)
                                d = NULL;
                        else prev->next = curr->next;
                        break;
                }
                else
                {
                        prev = curr;
                        curr = curr->next;
                }
        }
}


/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}
 	sector_t offset = req->sector * SECTOR_SIZE;
	unsigned int size = req->current_nr_sectors * SECTOR_SIZE;
	switch (rq_data_dir(req)){
		case READ:
			memcpy(req->buffer, d->data + offset, size);
			break;
		case WRITE:
			memcpy(d->data + offset, req->buffer, size);
			break;
		default:
			eprintk("ERROR : FAILURE TO R/W, INVALID REQ");
	}
	  
	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		int filp_writable = filp->f_mode & FMODE_WRITE;

	if (d==NULL) return -1;
	//if the user closes a file that holds a lock
	//release the lock and wake up the block queue
	if (filp->f_flags & F_OSPRD_LOCKED)
	{
		osp_spin_lock(&d->mutex);
		if (filp_writable)
		{
			d->write_locks--;
			d->write_pid = -1;
			filp->f_flags &= ~F_OSPRD_LOCKED;
			wake_up_all(&d->blockq);
		}
		else
		{
			d->read_locks--;
			remove_pid(current->pid,d->read_queue);
			filp->f_flags &= ~F_OSPRD_LOCKED;
			wake_up_all(&d->blockq);
			
		}
		osp_spin_unlock(&d->mutex);
	} 
	
  }
  
  return 0;
}

/*
* osprd_lock
*/

/*
* osprd_ioctl(inode, filp, cmd, arg)
*   Called to perform an ioctl on the named file.
*/
int osprd_ioctl(struct inode *inode, struct file *filp,
	unsigned int cmd, unsigned long arg)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	if (cmd == OSPRDIOCACQUIRE) {
	
	  if (d == NULL) return -1;
	  int i;
		if (filp_writable)
		{
			// check deadlock
			osp_spin_lock(&d->mutex);
			if (current->pid == d->write_pid)
				r = -EDEADLK;
			if (check_pid(current->pid, d->read_queue) == 1)
				r = -EDEADLK;
			osp_spin_unlock(&d->mutex);
			if (r == -EDEADLK) return r;
			
			//assign ticket number
                        osp_spin_lock(&d->mutex);
                        unsigned my_ticket_num = d->ticket_head;
                        d->ticket_head++;
			add_ticket(my_ticket_num,d->ticket_queue);
                        osp_spin_unlock(&d->mutex);
			
			//block and dealing with signal
			int sig = wait_event_interruptible(d->blockq, my_ticket_num == d->ticket_tail && d->read_locks ==0 && d->write_locks == 0);
				if (sig == -ERESTARTSYS)
				{
					osp_spin_lock(&d->mutex);
					remove_ticket(my_ticket_num,d->ticket_queue);
					osp_spin_unlock(&d->mutex);
					return sig;
				}


			//the process acquires the lock
			osp_spin_lock(&d->mutex);
			d->write_locks++;
			d->write_pid = current->pid;
			d->ticket_tail++;
			//while (check_ticket(d->ticket_tail,d->ticket_queue)==0 && d->ticket_tail<= d->ticket_head)
			//	d->ticket_tail++;
			filp->f_flags |= F_OSPRD_LOCKED;
			osp_spin_unlock(&d->mutex);
		}

		else
		{
			//check for deadlock
			osp_spin_lock(&d->mutex);
			if (d->write_pid == current->pid)
				r = -EDEADLK;
			osp_spin_unlock(&d->mutex);
			if (r == -EDEADLK)  return r;
			
			//assign ticket number
                        osp_spin_lock(&d->mutex);
                        unsigned my_ticket_num = d->ticket_head;
                        d->ticket_head++;
			add_ticket(my_ticket_num,d->ticket_queue);
                        osp_spin_unlock(&d->mutex);
	
			
			while(my_ticket_num != d->ticket_tail  || d->write_locks != 0)
                        {
			 	int sig = wait_event_interruptible(d->blockq,1);
				if(sig == -ERESTARTSYS)
				{	
					osp_spin_lock(&d->mutex);
					remove_ticket(my_ticket_num,d->ticket_queue);
					osp_spin_unlock(&d->mutex);
					return -sig;
				}
				schedule();
			} 


			//acquires the lock
			osp_spin_lock(&d->mutex);
			d->read_locks++;
			d->ticket_tail++;
			//while (check_ticket(d->ticket_tail,d->ticket_queue)==0 && d->ticket_tail <= d->ticket_head)
                        //        d->ticket_tail++;
			filp->f_flags |= F_OSPRD_LOCKED;
			add_pid(current->pid, d->read_queue);
			osp_spin_unlock(&d->mutex);
		}
	}

	else if (cmd == OSPRDIOCTRYACQUIRE) {

		// EXERCISE: ATTEMPT to lock the ramdisk.
		//
		// This is just like OSPRDIOCACQUIRE, except it should never
		// block.  If OSPRDIOCACQUIRE would block or return deadlock,
		// OSPRDIOCTRYACQUIRE should return -EBUSY.
		// Otherwise, if we can grant the lock request, return 0.

		// Your code here (instead of the next two lines).
		if (d == NULL) return -1;
		if (filp_writable)
		{
			
			osp_spin_lock(&d->mutex);

			if (current->pid == d->write_pid)
				r = -EBUSY;
			if (check_pid(current->pid, d->read_queue) == 1)
                                r = -EBUSY;

			if ( d->ticket_head != d->ticket_tail || d->read_locks != 0 || d->write_locks != 0)
				r = -EBUSY;
			osp_spin_unlock(&d->mutex);
			if (r == -EBUSY) return r;

			osp_spin_lock(&d->mutex);
		        unsigned my_ticket_num = d->ticket_head;
                        d->ticket_head++; 
			osp_spin_unlock(&d->mutex);
			
			
			osp_spin_lock(&d->mutex);
				filp->f_flags |= F_OSPRD_LOCKED;
				d->write_locks++;
				d->write_pid=current->pid;
				d->ticket_tail++;
			osp_spin_unlock(&d->mutex);

		}
		else
		{
			osp_spin_lock(&d->mutex);

			if (d->ticket_head != d->ticket_tail || d->write_locks != 0)
				r = -EBUSY;
			if (current->pid == d->write_pid)  
				r = -EBUSY;
			osp_spin_unlock(&d->mutex);
			if (r == -EBUSY)
				return r;
			                       
                        osp_spin_lock(&d->mutex);
				unsigned my_ticket_num = d->ticket_head;                       
				d->ticket_head++;
				filp->f_flags |= F_OSPRD_LOCKED;
				d->read_locks++;
				add_pid(current->pid,d->read_queue);
				d->ticket_tail++;
			osp_spin_unlock(&d->mutex);
		
		}
	}
	else if (cmd == OSPRDIOCRELEASE) {

		// EXERCISE: Unlock the ramdisk.
		//
		// If the file hasn't locked the ramdisk, return -EINVAL.
		// Otherwise, clear the lock from filp->f_flags, wake up
		// the wait queue, perform any additional accounting steps
		// you need, and return 0.

		// Your code here (instead of the next line).
		if (d == NULL) return -1;
		if ((filp->f_flags & F_OSPRD_LOCKED) == 0)
			return -EINVAL;
		else
		{
			osp_spin_lock(&d->mutex);
			if (filp_writable)
			{
				d->write_locks--;
				d->write_pid = -1;   
				filp->f_flags &= ~F_OSPRD_LOCKED;
			}
			else
			{
				d->read_locks--;
				remove_pid(current->pid,d->read_queue);
				filp->f_flags &= ~F_OSPRD_LOCKED;
			}
			wake_up_all(&d->blockq);
			osp_spin_unlock(&d->mutex);
		}
	}
	else
		r = -ENOTTY; /* unknown command */
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
	d->read_locks = 0;
	d->write_locks = 0;
	d->write_pid = -1;
	d->read_queue = NULL;
	d->ticket_queue = NULL;
	/*d->count = 0;
	d->skip = kzalloc(sizeof(int)*100,GFP_ATOMIC);*/
}




/*****************************************************************************/
	/* THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE! */
	/* */
	/*****************************************************************************/
	
	// Process a list of requests for a osprd_info_t.
	// Calls osprd_process_request for each element of the queue.
	
	static void osprd_process_request_queue(request_queue_t *q)
	{
	osprd_info_t *d = (osprd_info_t *)q->queuedata;
	struct request *req;
	
	while ((req = elv_next_request(q)) != NULL)
	osprd_process_request(d, req);
	}
	
	
	// Some particularly horrible stuff to get around some Linux issues:
	// the Linux block device interface doesn't let a block device find out
	// which file has been closed. We need this information.
	
	static struct file_operations osprd_blk_fops;
	static int(*blkdev_release)(struct inode *, struct file *);
	
	static int _osprd_release(struct inode *inode, struct file *filp)
	{
	if (file2osprd(filp))
	osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
	}
	
	static int _osprd_open(struct inode *inode, struct file *filp)
	{
	if (!osprd_blk_fops.open) {
	memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
	blkdev_release = osprd_blk_fops.release;
	osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
	}
	
	
	// The device operations structure.
	
	static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
	};
	
	
	// Given an open file, check whether that file corresponds to an OSP ramdisk.
	// If so, return a pointer to the ramdisk's osprd_info_t.
	// If not, return NULL.
	
	static osprd_info_t *file2osprd(struct file *filp)
	{
	if (filp) {
	struct inode *ino = filp->f_dentry->d_inode;
	if (ino->i_bdev
	&& ino->i_bdev->bd_disk
	&& ino->i_bdev->bd_disk->major == OSPRD_MAJOR
	&& ino->i_bdev->bd_disk->fops == &osprd_ops)
	return (osprd_info_t *)ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
	}
	
	
	// Call the function 'callback' with data 'user_data' for each of 'task's
	// open files.
	
	static void for_each_open_file(struct task_struct *task,
	void(*callback)(struct file *filp, osprd_info_t *user_data),
	osprd_info_t *user_data)
	{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
	#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
	struct files_struct *f = task->files;
	#else
	struct fdtable *f = task->files->fdt;
	#endif
	for (fd = 0; fd < f->max_fds; fd++)
	if (f->fd[fd])
	(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
	}
	
	
	// Destroy a osprd_info_t.
	
	static void cleanup_device(osprd_info_t *d)
	{
	wake_up_all(&d->blockq);
	if (d->gd) {
	del_gendisk(d->gd);
	put_disk(d->gd);
	}
	if (d->queue)
	blk_cleanup_queue(d->queue);
	if (d->data)
	vfree(d->data);
	}
	
	
	// Initialize a osprd_info_t.
	
	static int setup_device(osprd_info_t *d, int which)
	{
	memset(d, 0, sizeof(osprd_info_t));
	
	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
	return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);
	
	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
	return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;
	
	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
	return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);
	
	/* Call the setup function. */
	osprd_setup(d);
	
	return 0;
	}
	
	static void osprd_exit(void);
	
	
	// The kernel calls this function when the module is loaded.
	// It initializes the 4 osprd block devices.
	
	static int __init osprd_init(void)
	{
	int i, r;
	
	// shut up the compiler
	(void)for_each_open_file;
	#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void)osp_spin_unlock;
	#endif
	
	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
	printk(KERN_WARNING "osprd: unable to get major number\n");
	return -EBUSY;
	}
	
	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
	if (setup_device(&osprds[i], i) < 0)
	r = -EINVAL;
	
	if (r < 0) {
	printk(KERN_EMERG "osprd: can't set up device structures\n");
	osprd_exit();
	return -EBUSY;
	}
	else
	return 0;
	}
	
	
	// The kernel calls this function to unload the osprd module.
	// It destroys the osprd devices.
	
	static void osprd_exit(void)
	{
	int i;
	for (i = 0; i < NOSPRD; i++)
	cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
	}
	
	
	// Tell Linux to call those functions at init and exit time.
	module_init(osprd_init);
	module_exit(osprd_exit);
