// SPDX-License-Identifier: GPL-2.0
/*
 * Simple benchmark program that uses the various features of io_uring
 * to provide fast random access to a device/file. It has various
 * options that are control how we use io_uring, see the OPTIONS section
 * below. This uses the raw io_uring interface.
 *
 * Copyright (C) 2018-2019 Jens Axboe
 */
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

#include "liburing.h"
#include "barrier.h"

#define min(a, b)		((a < b) ? (a) : (b))

struct io_sq_ring {
	unsigned *head;/*队列读者指针*/
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;/*读者指针*/
	unsigned *tail;/*写者指针*/
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;/*保存cqe指针的数组*/
};

#define DEPTH			128

#define BATCH_SUBMIT		32
#define BATCH_COMPLETE		32

#define BS			4096

#define MAX_FDS			16

static unsigned sq_ring_mask, cq_ring_mask;

struct file {
	unsigned long max_blocks;/*占用的块数*/
	unsigned pending_ios;
	int real_fd;/*文件对应的fd*/
	int fixed_fd;
};

struct submitter {
	pthread_t thread;
	int ring_fd;
	struct drand48_data rand;
	struct io_sq_ring sq_ring;/*发送队列（读请求）*/
	struct io_uring_sqe *sqes;
	struct iovec iovecs[DEPTH];/*读取缓冲区*/
	struct io_cq_ring cq_ring;/*响应队列（读完成）*/
	int inflight;/*待完成的io请求（已发出）*/
	unsigned long reaps;/*已响应的io请求*/
	unsigned long done;/*已完成的io请求*/
	unsigned long calls;
	volatile int finish;

	__s32 *fds;

	struct file files[MAX_FDS];
	unsigned nr_files;
	unsigned cur_file;
};

static struct submitter submitters[1];
static volatile int finish;

/*
 * OPTIONS: Set these to test the various features of io_uring.
 */
static int polled = 1;		/* use IO polling */
static int fixedbufs = 1;	/* use fixed user buffers */
static int register_files = 1;	/* use fixed files */
static int buffered = 0;	/* use buffered IO, not O_DIRECT */
static int sq_thread_poll = 0;	/* use kernel submission/poller thread */
static int sq_thread_cpu = -1;	/* pin above thread to this CPU */
static int do_nop = 0;		/* no-op SQ ring commands */

static int io_uring_register_buffers(struct submitter *s)
{
	if (do_nop)
		return 0;

	return io_uring_register(s->ring_fd, IORING_REGISTER_BUFFERS/*注册固定buffer*/, s->iovecs,
					DEPTH);
}

static int io_uring_register_files(struct submitter *s)
{
	unsigned i;

	if (do_nop)
		return 0;

	s->fds = calloc(s->nr_files, sizeof(__s32));
	for (i = 0; i < s->nr_files; i++) {
		s->fds[i] = s->files[i].real_fd;
		s->files[i].fixed_fd = i;
	}

	return io_uring_register(s->ring_fd, IORING_REGISTER_FILES/*注册固定文件*/, s->fds,
					s->nr_files);
}

static int lk_gettid(void)
{
	return syscall(__NR_gettid);
}

static unsigned file_depth(struct submitter *s)
{
	return (DEPTH + s->nr_files - 1) / s->nr_files;
}

static void init_io(struct submitter *s, unsigned index)
{
    /*取sqe*/
	struct io_uring_sqe *sqe = &s->sqes[index];
	unsigned long offset;
	struct file *f;
	long r;

	if (do_nop) {
	    /*不做操作，只设置NOP*/
		sqe->opcode = IORING_OP_NOP;
		return;
	}

	if (s->nr_files == 1) {
	    /*仅有一个文件的情况，取0号文件*/
		f = &s->files[0];
	} else {
	    /*有多个文件，取当前索引对应的文件*/
		f = &s->files[s->cur_file];
		if (f->pending_ios >= file_depth(s)) {
		    /*当前索引对应的文件pending的io数过多，换一个文件*/
			s->cur_file++;
			if (s->cur_file == s->nr_files)
				s->cur_file = 0;
			f = &s->files[s->cur_file];
		}
	}

	/*此文件pending的io数加1*/
	f->pending_ios++;

	/*产生随机数，生成一个随机的读写偏移位置*/
	lrand48_r(&s->rand, &r);
	offset = (r % (f->max_blocks - 1)) * BS;

	if (register_files) {
		sqe->flags = IOSQE_FIXED_FILE;
		sqe->fd = f->fixed_fd;
	} else {
		sqe->flags = 0;
		sqe->fd = f->real_fd;
	}
	if (fixedbufs) {
	    /*固定读取*/
		sqe->opcode = IORING_OP_READ_FIXED;
		sqe->addr = (unsigned long) s->iovecs[index].iov_base;
		sqe->len = BS;
		sqe->buf_index = index;
	} else {
	    /*readv读取*/
		sqe->opcode = IORING_OP_READV;
		sqe->addr = (unsigned long) &s->iovecs[index];
		sqe->len = 1;
		sqe->buf_index = 0;
	}
	sqe->ioprio = 0;
	sqe->off = offset;
	sqe->user_data = (unsigned long) f;
}

/*尽量准备max_ios个sqe io*/
static int prep_more_ios(struct submitter *s, unsigned max_ios)
{
	struct io_sq_ring *ring = &s->sq_ring;
	unsigned index, tail, next_tail, prepped = 0;

	/*取ring->tail*/
	next_tail = tail = *ring->tail;
	do {
		next_tail++;
		read_barrier();
		if (next_tail == *ring->head)
		    /*队列为满，退出*/
			break;

		/*确定要写入的seq index*/
		index = tail & sq_ring_mask;
		/*填充seq*/
		init_io(s, index);
		ring->array[index] = index;
		prepped++;
		tail = next_tail;
	} while (prepped < max_ios);

	/*更新tail指针*/
	if (*ring->tail != tail) {
		/* order tail store with writes to sqes above */
		write_barrier();
		*ring->tail = tail;
		write_barrier();
	}
	return prepped;
}

/*取文件大小*/
static int get_file_size(struct file *f)
{
	struct stat st;

	if (fstat(f->real_fd, &st) < 0)
		return -1;
	if (S_ISBLK(st.st_mode)) {
	    /*针对块设备，取占用的块数*/
		unsigned long long bytes;

		if (ioctl(f->real_fd, BLKGETSIZE64, &bytes) != 0)
			return -1;

		f->max_blocks = bytes / BS;
		return 0;
	} else if (S_ISREG(st.st_mode)) {
	    /*针对普通文件，取占用的块数*/
		f->max_blocks = st.st_size / BS;
		return 0;
	}

	return -1;
}

static int reap_events(struct submitter *s)
{
	struct io_cq_ring *ring = &s->cq_ring;
	struct io_uring_cqe *cqe;
	unsigned head, reaped = 0;

	/*取cq的指针*/
	head = *ring->head;
	do {
		struct file *f;

		read_barrier();
		if (head == *ring->tail)
		    /*队列已为空，退出*/
			break;
		/*拿到cqe*/
		cqe = &ring->cqes[head & cq_ring_mask];
		if (!do_nop) {
		    /*获得cqe对应的file*/
			f = (struct file *) (uintptr_t) cqe->user_data;
			f->pending_ios--;
			if (cqe->res != BS) {
				printf("io: unexpected ret=%d\n", cqe->res);
				if (polled && cqe->res == -EOPNOTSUPP)
					printf("Your filesystem doesn't support poll\n");
				return -1;
			}
		}
		reaped++;/*记录收获的数目*/
		head++;/*head指针前移*/
	} while (1);

	s->inflight -= reaped;
	*ring->head = head;/*更新head*/
	write_barrier();
	return reaped;/*返回reap的数目*/
}

static void *submitter_fn(void *data)
{
	struct submitter *s = data;
	struct io_sq_ring *ring = &s->sq_ring;
	int ret, prepped;

	printf("submitter=%d\n", lk_gettid());

	/*初始化随机值*/
	srand48_r(pthread_self(), &s->rand);

	prepped = 0;
	do {
		int to_wait, to_submit, this_reap, to_prep;

		if (!prepped && s->inflight < DEPTH) {
			to_prep = min(DEPTH - s->inflight, BATCH_SUBMIT);
			/*尽量准备足够大的(to_prep)io*/
			prepped = prep_more_ios(s, to_prep);
		}
		/*待响应的io数增大*/
		s->inflight += prepped;
submit_more:
		to_submit = prepped;
submit:
		if (to_submit && (s->inflight + to_submit <= DEPTH))
			to_wait = 0;
		else
			to_wait = min(s->inflight + to_submit, BATCH_COMPLETE);

		/*
		 * Only need to call io_uring_enter if we're not using SQ thread
		 * poll, or if IORING_SQ_NEED_WAKEUP is set.
		 */
		if (!sq_thread_poll || (*ring->flags & IORING_SQ_NEED_WAKEUP)) {
			unsigned flags = 0;

			if (to_wait)
				flags = IORING_ENTER_GETEVENTS;
			if ((*ring->flags & IORING_SQ_NEED_WAKEUP))
				flags |= IORING_ENTER_SQ_WAKEUP;
			ret = io_uring_enter(s->ring_fd, to_submit, to_wait,
						flags, NULL);
			s->calls++;
		}

		/*
		 * For non SQ thread poll, we already got the events we needed
		 * through the io_uring_enter() above. For SQ thread poll, we
		 * need to loop here until we find enough events.
		 */
		this_reap = 0;
		do {
			int r;
			r = reap_events(s);
			if (r == -1) {
			    /*不支持poll*/
				s->finish = 1;
				break;
			} else if (r > 0)
				this_reap += r;
		} while (sq_thread_poll && this_reap < to_wait);
		s->reaps += this_reap;

		if (ret >= 0) {
			if (!ret) {
				to_submit = 0;
				if (s->inflight)
					goto submit;
				continue;
			} else if (ret < to_submit) {
				int diff = to_submit - ret;

				s->done += ret;
				prepped -= diff;
				goto submit_more;
			}
			s->done += ret;
			prepped = 0;
			continue;
		} else if (ret < 0) {
			if (errno == EAGAIN) {
				if (s->finish)
					break;
				if (this_reap)
					goto submit;
				to_submit = 0;
				goto submit;
			}
			printf("io_submit: %s\n", strerror(errno));
			break;
		}
	} while (!s->finish);

	finish = 1;
	return NULL;
}

static void sig_int(int sig)
{
	printf("Exiting on signal %d\n", sig);
	submitters[0].finish = 1;
	finish = 1;
}

static void arm_sig_int(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
}

static int setup_ring(struct submitter *s)
{
	struct io_sq_ring *sring = &s->sq_ring;
	struct io_cq_ring *cring = &s->cq_ring;
	struct io_uring_params p;
	int ret, fd;
	void *ptr;

	memset(&p, 0, sizeof(p));

	if (polled && !do_nop)
		p.flags |= IORING_SETUP_IOPOLL;
	if (sq_thread_poll) {
		p.flags |= IORING_SETUP_SQPOLL;
		if (sq_thread_cpu != -1) {
			p.flags |= IORING_SETUP_SQ_AFF;
			p.sq_thread_cpu = sq_thread_cpu;
		}
	}

	/*请求kernel创建io_uring，kernel会填充p结构体部分字段*/
	fd = io_uring_setup(DEPTH, &p);
	if (fd < 0) {
		perror("io_uring_setup");
		return 1;
	}
	s->ring_fd = fd;

	if (fixedbufs) {
	    /*注册固定buffer*/
		ret = io_uring_register_buffers(s);
		if (ret < 0) {
			perror("io_uring_register_buffers");
			return 1;
		}
	}

	if (register_files) {
	    /*注册固定文件*/
		ret = io_uring_register_files(s);
		if (ret < 0) {
			perror("io_uring_register_files");
			return 1;
		}
	}

	/*映射生产者ring*/
	ptr = mmap(0, p.sq_off.array + p.sq_entries * sizeof(__u32),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQ_RING);
	printf("sq_ring ptr = 0x%p\n", ptr);
	sring->head = ptr + p.sq_off.head;
	sring->tail = ptr + p.sq_off.tail;
	sring->ring_mask = ptr + p.sq_off.ring_mask;
	sring->ring_entries = ptr + p.sq_off.ring_entries;
	sring->flags = ptr + p.sq_off.flags;
	sring->array = ptr + p.sq_off.array;
	sq_ring_mask = *sring->ring_mask;

	/*映射sqe数组*/
	s->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQES);
	printf("sqes ptr    = 0x%p\n", s->sqes);

	/*映射消费者ring*/
	ptr = mmap(0, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	printf("cq_ring ptr = 0x%p\n", ptr);
	cring->head = ptr + p.cq_off.head;
	cring->tail = ptr + p.cq_off.tail;
	cring->ring_mask = ptr + p.cq_off.ring_mask;
	cring->ring_entries = ptr + p.cq_off.ring_entries;
	cring->cqes = ptr + p.cq_off.cqes;
	cq_ring_mask = *cring->ring_mask;
	return 0;
}

static void file_depths(char *buf)
{
	struct submitter *s = &submitters[0];
	unsigned i;
	char *p;

	buf[0] = '\0';
	p = buf;
	for (i = 0; i < s->nr_files; i++) {
		struct file *f = &s->files[i];

		if (i + 1 == s->nr_files)
			p += sprintf(p, "%d", f->pending_ios);
		else
			p += sprintf(p, "%d, ", f->pending_ios);
	}
}

int main(int argc, char *argv[])
{
	struct submitter *s = &submitters[0];
	unsigned long done, calls, reap;
	int err, i, flags, fd;
	char *fdepths;
	void *ret;

	if (!do_nop && argc < 2) {
	    /*参数不足*/
		printf("%s: filename\n", argv[0]);
		return 1;
	}

	/*只读打开，测试读操作*/
	flags = O_RDONLY | O_NOATIME;
	if (!buffered)
		flags |= O_DIRECT;

	/*打开用户提定的文件，填充s->files*/
	i = 1;
	while (!do_nop && i < argc) {
		struct file *f;

		if (s->nr_files == MAX_FDS) {
		    /*文件数目达到最大值，退出*/
			printf("Max number of files (%d) reached\n", MAX_FDS);
			break;
		}

		/*打开此文件*/
		fd = open(argv[i], flags);
		if (fd < 0) {
			perror("open");
			return 1;
		}

		f = &s->files[s->nr_files];
		f->real_fd = fd;
		if (get_file_size(f)) {
		    /*获取文件大小失败*/
			printf("failed getting size of device/file\n");
			return 1;
		}
		if (f->max_blocks <= 1) {
		    /*文件块数过小*/
			printf("Zero file/device size?\n");
			return 1;
		}
		f->max_blocks--;

		printf("Added file %s\n", argv[i]);
		s->nr_files++;
		i++;
	}

	if (fixedbufs) {
		struct rlimit rlim;

		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
			perror("setrlimit");
			return 1;
		}
	}

	arm_sig_int();

	/*申请DEPTH个BS（用于数据读取缓冲区），按BS大小进行对齐*/
	for (i = 0; i < DEPTH; i++) {
		void *buf;

		if (posix_memalign(&buf, BS, BS)) {
			printf("failed alloc\n");
			return 1;
		}
		s->iovecs[i].iov_base = buf;
		s->iovecs[i].iov_len = BS;
	}

	/*初始化ring*/
	err = setup_ring(s);
	if (err) {
		printf("ring setup failed: %s, %d\n", strerror(errno), err);
		return 1;
	}
	printf("polled=%d, fixedbufs=%d, buffered=%d", polled, fixedbufs, buffered);
	printf(" QD=%d, sq_ring=%d, cq_ring=%d\n", DEPTH, *s->sq_ring.ring_entries, *s->cq_ring.ring_entries);

	/*创建线程，执行submitter_fn*/
	pthread_create(&s->thread, NULL, submitter_fn, s);

	fdepths = malloc(8 * s->nr_files);
	reap = calls = done = 0;
	do {
		unsigned long this_done = 0;
		unsigned long this_reap = 0;
		unsigned long this_call = 0;
		unsigned long rpc = 0, ipc = 0;

		sleep(1);
		this_done += s->done;
		this_call += s->calls;
		this_reap += s->reaps;
		if (this_call - calls) {
			rpc = (this_done - done) / (this_call - calls);
			ipc = (this_reap - reap) / (this_call - calls);
		} else
			rpc = ipc = -1;
		file_depths(fdepths);
		/*计算并显示iops*/
		printf("IOPS=%lu, IOS/call=%ld/%ld, inflight=%u (%s)\n",
				this_done - done, rpc, ipc, s->inflight,
				fdepths);
		done = this_done;
		calls = this_call;
		reap = this_reap;
	} while (!finish);

	pthread_join(s->thread, &ret);
	close(s->ring_fd);
	free(fdepths);
	return 0;
}
