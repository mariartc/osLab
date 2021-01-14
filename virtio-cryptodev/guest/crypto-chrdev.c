/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);         //crdrvdata is a global struct in module.c
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof; //crypto open file
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0, num_in = 0;
	struct virtqueue *vq;
	unsigned long flags;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	sema_init(&crdev->lock, 1); // initiallize semaphore

	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	vq = crdev->vq;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;

	if(down_interruptible(&crdev->lock)) //lock crypto device
		return -ERESTARTSYS;

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(vq, &len) == NULL); // do nothing while waiting

	crof->host_fd = *host_fd;

	up(&crdev->lock); //unlock crypto device
	
	printk(KERN_DEBUG "host_fd line 129: %d", crof->host_fd);

	/* If host failed to open() return -ENODEV. */
	if(crof->host_fd < 0){
		debug("Host failed to open(). Leaving");
		return -ENODEV;
	}

fail:
	kfree(syscall_type);
	kfree(host_fd);
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0, err, *host_fd;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0, num_in = 0;
	struct virtqueue *vq = crdev->vq;
	unsigned long flags;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Send data to the host.
	 **/
	if(down_interruptible(&crdev->lock)) //lock crypto device
		return -ERESTARTSYS;

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(vq, &len) == NULL); // do nothing while waiting

	up(&crdev->lock); //unlock crypto device

	kfree(syscall_type);
	kfree(host_fd);
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err, *host_fd;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, cmd_sg, session_sg, sess_ses_sg, session_key_sg, crypt_sg, crypto_src_sg, crypto_dst_sg, crypto_iv_sg, host_return_val_sg, *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	int *host_return_val = NULL;
	unsigned int *syscall_type, *ioctl_cmd = NULL;
	unsigned long flags;
	struct session_op *user_session, *copied_session = NULL;
	struct crypt_op *user_crypt, *copied_crypt = NULL;
	__u8 *session_key = NULL, *crypto_src = NULL, *crypto_dst = NULL, *crypto_iv = NULL;
	__u32 *user_sess_ses, *copied_sess_ses = NULL;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;
	
	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &cmd_sg;

	printk(KERN_DEBUG "*ioctl_cmd: %u", *ioctl_cmd);
	printk(KERN_DEBUG "cmd: %u", cmd);
	printk(KERN_DEBUG "host_fd: %d", crof->host_fd);

	// in order to avoid uninitialized error in `copy_to_user`
	user_session = (struct session_op *)arg;
	user_crypt = (struct crypt_op *)arg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");

		user_session = (struct session_op *)arg;

		copied_session = kzalloc(sizeof(*copied_session), GFP_KERNEL);
		if((ret = copy_from_user(copied_session, user_session, sizeof(*copied_session)))) {
			debug("Failed to copy_from_user (copied_session).");
			goto fail;
		}

		debug("after copy_from_user(&copied_session, user_session, sizeof(struct session_op))");

		session_key = kzalloc((copied_session->keylen)+1, GFP_KERNEL);
		if((ret = copy_from_user(session_key, user_session->key, (user_session->keylen)*sizeof(__u8)))){
			debug("Failed to copy_from_user (session_key).");
			goto fail;
		}
		session_key[copied_session->keylen]='\0'; // ensure null char at the end of session_key

		// we could also do the same for mackeylen - mackey, but we don't use it

		sg_init_one(&session_sg, copied_session, sizeof(*copied_session));
		sgs[num_out + num_in++] = &session_sg;
		debug("after sgs[num_out + num_in++] = &session_sg;");
		sg_init_one(&session_key_sg, session_key, (copied_session->keylen)+1);
		sgs[num_out + num_in++] = &session_key_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");

		user_sess_ses = (__u32 *)arg;

		copied_sess_ses = kzalloc(sizeof(*copied_sess_ses), GFP_KERNEL);
		if((ret = copy_from_user(copied_sess_ses, user_sess_ses, sizeof(*copied_sess_ses)))){
			debug("Failed to copy_from_user (copied_sess_ses).");
			goto fail;
		}

		sg_init_one(&sess_ses_sg, copied_sess_ses, sizeof(*copied_sess_ses));
		sgs[num_out + num_in++] = &sess_ses_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");

		copied_crypt = kzalloc(sizeof(*copied_crypt), GFP_KERNEL);
		if((ret = copy_from_user(copied_crypt, user_crypt, sizeof(*copied_crypt)))) {
			debug("Failed to copy_from_user (copied_crypt).");
			goto fail;
		}

		crypto_src = kzalloc(copied_crypt->len * sizeof(__u8), GFP_KERNEL);
		if((ret = copy_from_user(crypto_src, user_crypt->src, copied_crypt->len * sizeof(__u8)))) {
			debug("Failed to copy_from_user (crypto_src).");
			goto fail;
		}

		crypto_dst = kzalloc(copied_crypt->len * sizeof(__u8), GFP_KERNEL);

		crypto_iv = kzalloc(16 * sizeof(__u8), GFP_KERNEL);
		if((ret = copy_from_user(crypto_iv, user_crypt->iv, 16 * sizeof(__u8)))) {
			debug("Failed to copy_from_user (crypto_iv).");
			goto fail;
		}

		sg_init_one(&crypt_sg, copied_crypt, sizeof(*copied_crypt));
		sgs[num_out + num_in++] = &crypt_sg;
		sg_init_one(&crypto_src_sg, crypto_src, copied_crypt->len * sizeof(__u8));
		sgs[num_out + num_in++] = &crypto_src_sg;
		sg_init_one(&crypto_dst_sg, crypto_dst, copied_crypt->len * sizeof(__u8));
		sgs[num_out + num_in++] = &crypto_dst_sg;
		sg_init_one(&crypto_iv_sg, crypto_iv, 16 * sizeof(__u8));
		sgs[num_out + num_in++] = &crypto_iv_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);
	sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
	sgs[num_out + num_in++] = &host_return_val_sg;


	/**
	 * Wait for the host to process our data.
	 **/
	if(down_interruptible(&crdev->lock)) //lock crypto device
		return -ERESTARTSYS;

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	if(cmd == CIOCGSESSION) {
		if((ret = copy_to_user(user_session, copied_session, sizeof(*copied_session)))) {
			debug("Failed to copy_to_user (user_session).");
		}
	}

	if(cmd == CIOCCRYPT) {
		if((ret = copy_to_user(user_crypt->dst, crypto_dst, copied_crypt->len * sizeof(__u8)))) {
			debug("Failed to copy_to_user (user_crypt->dst).");
		}
	}

	ret = *host_return_val;
	printk(KERN_DEBUG "*host_return_val: %d", *host_return_val);

	up(&crdev->lock); //unlock crypto device

fail:
	switch (cmd) {
		case CIOCGSESSION:
			kfree(copied_session);
			kfree(session_key);
			break;

		case CIOCFSESSION:
			kfree(copied_sess_ses);
			break;

		case CIOCCRYPT:
			kfree(copied_crypt);
			kfree(crypto_src);
			kfree(crypto_dst);
			kfree(crypto_iv);
			break;
	}

	kfree(syscall_type);
	kfree(host_fd);
	kfree(ioctl_cmd);
	kfree(host_return_val);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
