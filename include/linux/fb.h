/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FB_H
#define _LINUX_FB_H

#include <linux/refcount.h>
#include <linux/kgdb.h>
#include <uapi/linux/fb.h>

#define FBIO_CURSOR            _IOWR('F', 0x08, struct fb_cursor_user)

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/list.h>
#include <linux/backlight.h>
#include <linux/slab.h>

#include <asm/fb.h>

struct vm_area_struct;
struct fb_info;
struct device;
struct file;
struct videomode;
struct device_node;

/* Definitions below are used in the parsed monitor specs */
#define FB_DPMS_ACTIVE_OFF	1
#define FB_DPMS_SUSPEND		2
#define FB_DPMS_STANDBY		4

#define FB_DISP_DDI		1
#define FB_DISP_ANA_700_300	2
#define FB_DISP_ANA_714_286	4
#define FB_DISP_ANA_1000_400	8
#define FB_DISP_ANA_700_000	16

#define FB_DISP_MONO		32
#define FB_DISP_RGB		64
#define FB_DISP_MULTI		128
#define FB_DISP_UNKNOWN		256

#define FB_SIGNAL_NONE		0
#define FB_SIGNAL_BLANK_BLANK	1
#define FB_SIGNAL_SEPARATE	2
#define FB_SIGNAL_COMPOSITE	4
#define FB_SIGNAL_SYNC_ON_GREEN	8
#define FB_SIGNAL_SERRATION_ON	16

#define FB_MISC_PRIM_COLOR	1
#define FB_MISC_1ST_DETAIL	2	/* First Detailed Timing is preferred */
#define FB_MISC_HDMI		4
struct fb_chroma {
	__u32 redx;	/* in fraction of 1024 */
	__u32 greenx;
	__u32 bluex;
	__u32 whitex;
	__u32 redy;
	__u32 greeny;
	__u32 bluey;
	__u32 whitey;
};

struct fb_monspecs {
	struct fb_chroma chroma;
	struct fb_videomode *modedb;	/* mode database */
	__u8  manufacturer[4];		/* Manufacturer */
	__u8  monitor[14];		/* Monitor String */
	__u8  serial_no[14];		/* Serial Number */
	__u8  ascii[14];		/* ? */
	__u32 modedb_len;		/* mode database length */
	__u32 model;			/* Monitor Model */
	__u32 serial;			/* Serial Number - Integer */
	__u32 year;			/* Year manufactured */
	__u32 week;			/* Week Manufactured */
	__u32 hfmin;			/* hfreq lower limit (Hz) */
	__u32 hfmax;			/* hfreq upper limit (Hz) */
	__u32 dclkmin;			/* pixelclock lower limit (Hz) */
	__u32 dclkmax;			/* pixelclock upper limit (Hz) */
	__u16 input;			/* display type - see FB_DISP_* */
	__u16 dpms;			/* DPMS support - see FB_DPMS_ */
	__u16 signal;			/* Signal Type - see FB_SIGNAL_* */
	__u16 vfmin;			/* vfreq lower limit (Hz) */
	__u16 vfmax;			/* vfreq upper limit (Hz) */
	__u16 gamma;			/* Gamma - in fractions of 100 */
	__u16 gtf	: 1;		/* supports GTF */
	__u16 misc;			/* Misc flags - see FB_MISC_* */
	__u8  version;			/* EDID version... */
	__u8  revision;			/* ...and revision */
	__u8  max_x;			/* Maximum horizontal size (cm) */
	__u8  max_y;			/* Maximum vertical size (cm) */
};

struct fb_cmap_user {
	__u32 start;			/* First entry	*/
	__u32 len;			/* Number of entries */
	__u16 __user *red;		/* Red values	*/
	__u16 __user *green;
	__u16 __user *blue;
	__u16 __user *transp;		/* transparency, can be NULL */
};

struct fb_image_user {
	__u32 dx;			/* Where to place image */
	__u32 dy;
	__u32 width;			/* Size of image */
	__u32 height;
	__u32 fg_color;			/* Only used when a mono bitmap */
	__u32 bg_color;
	__u8  depth;			/* Depth of the image */
	const char __user *data;	/* Pointer to image data */
	struct fb_cmap_user cmap;	/* color map info */
};

struct fb_cursor_user {
	__u16 set;			/* what to set */
	__u16 enable;			/* cursor on/off */
	__u16 rop;			/* bitop operation */
	const char __user *mask;	/* cursor mask bits */
	struct fbcurpos hot;		/* cursor hot spot */
	struct fb_image_user image;	/* Cursor image */
};

/*
 * Register/unregister for framebuffer events
 */

/*	The resolution of the passed in fb_info about to change */
#define FB_EVENT_MODE_CHANGE		0x01

#ifdef CONFIG_GUMSTIX_AM200EPD
/* only used by mach-pxa/am200epd.c */
#define FB_EVENT_FB_REGISTERED          0x05
#define FB_EVENT_FB_UNREGISTERED        0x06
#endif

/*      A display blank is requested       */
#define FB_EVENT_BLANK                  0x09

struct fb_event {
	struct fb_info *info;
	void *data;
};

struct fb_blit_caps {
	u32 x;
	u32 y;
	u32 len;
	u32 flags;
};

#ifdef CONFIG_FB_NOTIFY
extern int fb_register_client(struct notifier_block *nb);
extern int fb_unregister_client(struct notifier_block *nb);
extern int fb_notifier_call_chain(unsigned long val, void *v);
#else
static inline int fb_register_client(struct notifier_block *nb)
{
	return 0;
};

static inline int fb_unregister_client(struct notifier_block *nb)
{
	return 0;
};

static inline int fb_notifier_call_chain(unsigned long val, void *v)
{
	return 0;
};
#endif

/*
 * Pixmap structure definition
 *
 * The purpose of this structure is to translate data
 * from the hardware independent format of fbdev to what
 * format the hardware needs.
 */

#define FB_PIXMAP_DEFAULT 1     /* used internally by fbcon */
#define FB_PIXMAP_SYSTEM  2     /* memory is in system RAM  */
#define FB_PIXMAP_IO      4     /* memory is iomapped       */
#define FB_PIXMAP_SYNC    256   /* set if GPU can DMA       */

struct fb_pixmap {
	u8  *addr;		/* pointer to memory			*/
	u32 size;		/* size of buffer in bytes		*/
	u32 offset;		/* current offset to buffer		*/
	u32 buf_align;		/* byte alignment of each bitmap	*/
	u32 scan_align;		/* alignment per scanline		*/
	u32 access_align;	/* alignment per read/write (bits)	*/
	u32 flags;		/* see FB_PIXMAP_*			*/
	u32 blit_x;             /* supported bit block dimensions (1-32)*/
	u32 blit_y;             /* Format: blit_x = 1 << (width - 1)    */
	                        /*         blit_y = 1 << (height - 1)   */
	                        /* if 0, will be set to 0xffffffff (all)*/
	/* access methods */
	void (*writeio)(struct fb_info *info, void __iomem *dst, void *src, unsigned int size);
	void (*readio) (struct fb_info *info, void *dst, void __iomem *src, unsigned int size);
};

#ifdef CONFIG_FB_DEFERRED_IO
struct fb_deferred_io_pageref {
	struct page *page;
	unsigned long offset;
	/* private */
	struct list_head list;
};

struct fb_deferred_io {
	/* delay between mkwrite and deferred handler */
	unsigned long delay;
	bool sort_pagereflist; /* sort pagelist by offset */
	int open_count; /* number of opened files; protected by fb_info lock */
	struct mutex lock; /* mutex that protects the pageref list */
	struct list_head pagereflist; /* list of pagerefs for touched pages */
	/* callback */
	void (*deferred_io)(struct fb_info *info, struct list_head *pagelist);
};
#endif

/*
 * Frame buffer operations
 *
 * LOCKING NOTE: those functions must _ALL_ be called with the console
 * semaphore held, this is the only suitable locking mechanism we have
 * in 2.6. Some may be called at interrupt time at this point though.
 *
 * The exception to this is the debug related hooks.  Putting the fb
 * into a debug state (e.g. flipping to the kernel console) and restoring
 * it must be done in a lock-free manner, so low level drivers should
 * keep track of the initial console (if applicable) and may need to
 * perform direct, unlocked hardware writes in these hooks.
 */

struct fb_ops {
	/* open/release and usage marking */
	struct module *owner;
	int (*fb_open)(struct fb_info *info, int user);
	int (*fb_release)(struct fb_info *info, int user);

	/* For framebuffers with strange non linear layouts or that do not
	 * work with normal memory mapped access
	 */
	ssize_t (*fb_read)(struct fb_info *info, char __user *buf,
			   size_t count, loff_t *ppos);
	ssize_t (*fb_write)(struct fb_info *info, const char __user *buf,
			    size_t count, loff_t *ppos);

	/* checks var and eventually tweaks it to something supported,
	 * DO NOT MODIFY PAR */
	int (*fb_check_var)(struct fb_var_screeninfo *var, struct fb_info *info);

	/* set the video mode according to info->var */
	int (*fb_set_par)(struct fb_info *info);

	/* set color register */
	int (*fb_setcolreg)(unsigned regno, unsigned red, unsigned green,
			    unsigned blue, unsigned transp, struct fb_info *info);

	/* set color registers in batch */
	int (*fb_setcmap)(struct fb_cmap *cmap, struct fb_info *info);

	/* blank display */
	int (*fb_blank)(int blank, struct fb_info *info);

	/* pan display */
	int (*fb_pan_display)(struct fb_var_screeninfo *var, struct fb_info *info);

	/* Draws a rectangle */
	void (*fb_fillrect) (struct fb_info *info, const struct fb_fillrect *rect);
	/* Copy data from area to another */
	void (*fb_copyarea) (struct fb_info *info, const struct fb_copyarea *region);
	/* Draws a image to the display */
	void (*fb_imageblit) (struct fb_info *info, const struct fb_image *image);

	/* Draws cursor */
	int (*fb_cursor) (struct fb_info *info, struct fb_cursor *cursor);

	/* wait for blit idle, optional */
	int (*fb_sync)(struct fb_info *info);

	/* perform fb specific ioctl (optional) */
	int (*fb_ioctl)(struct fb_info *info, unsigned int cmd,
			unsigned long arg);

	/* Handle 32bit compat ioctl (optional) */
	int (*fb_compat_ioctl)(struct fb_info *info, unsigned cmd,
			unsigned long arg);

	/* perform fb specific mmap */
	int (*fb_mmap)(struct fb_info *info, struct vm_area_struct *vma);

	/* get capability given var */
	void (*fb_get_caps)(struct fb_info *info, struct fb_blit_caps *caps,
			    struct fb_var_screeninfo *var);

	/* teardown any resources to do with this framebuffer */
	void (*fb_destroy)(struct fb_info *info);

	/* called at KDB enter and leave time to prepare the console */
	int (*fb_debug_enter)(struct fb_info *info);
	int (*fb_debug_leave)(struct fb_info *info);
};

#ifdef CONFIG_FB_TILEBLITTING
#define FB_TILE_CURSOR_NONE        0
#define FB_TILE_CURSOR_UNDERLINE   1
#define FB_TILE_CURSOR_LOWER_THIRD 2
#define FB_TILE_CURSOR_LOWER_HALF  3
#define FB_TILE_CURSOR_TWO_THIRDS  4
#define FB_TILE_CURSOR_BLOCK       5

struct fb_tilemap {
	__u32 width;                /* width of each tile in pixels */
	__u32 height;               /* height of each tile in scanlines */
	__u32 depth;                /* color depth of each tile */
	__u32 length;               /* number of tiles in the map */
	const __u8 *data;           /* actual tile map: a bitmap array, packed
				       to the nearest byte */
};

struct fb_tilerect {
	__u32 sx;                   /* origin in the x-axis */
	__u32 sy;                   /* origin in the y-axis */
	__u32 width;                /* number of tiles in the x-axis */
	__u32 height;               /* number of tiles in the y-axis */
	__u32 index;                /* what tile to use: index to tile map */
	__u32 fg;                   /* foreground color */
	__u32 bg;                   /* background color */
	__u32 rop;                  /* raster operation */
};

struct fb_tilearea {
	__u32 sx;                   /* source origin in the x-axis */
	__u32 sy;                   /* source origin in the y-axis */
	__u32 dx;                   /* destination origin in the x-axis */
	__u32 dy;                   /* destination origin in the y-axis */
	__u32 width;                /* number of tiles in the x-axis */
	__u32 height;               /* number of tiles in the y-axis */
};

struct fb_tileblit {
	__u32 sx;                   /* origin in the x-axis */
	__u32 sy;                   /* origin in the y-axis */
	__u32 width;                /* number of tiles in the x-axis */
	__u32 height;               /* number of tiles in the y-axis */
	__u32 fg;                   /* foreground color */
	__u32 bg;                   /* background color */
	__u32 length;               /* number of tiles to draw */
	__u32 *indices;             /* array of indices to tile map */
};

struct fb_tilecursor {
	__u32 sx;                   /* cursor position in the x-axis */
	__u32 sy;                   /* cursor position in the y-axis */
	__u32 mode;                 /* 0 = erase, 1 = draw */
	__u32 shape;                /* see FB_TILE_CURSOR_* */
	__u32 fg;                   /* foreground color */
	__u32 bg;                   /* background color */
};

struct fb_tile_ops {
	/* set tile characteristics */
	void (*fb_settile)(struct fb_info *info, struct fb_tilemap *map);

	/* all dimensions from hereon are in terms of tiles */

	/* move a rectangular region of tiles from one area to another*/
	void (*fb_tilecopy)(struct fb_info *info, struct fb_tilearea *area);
	/* fill a rectangular region with a tile */
	void (*fb_tilefill)(struct fb_info *info, struct fb_tilerect *rect);
	/* copy an array of tiles */
	void (*fb_tileblit)(struct fb_info *info, struct fb_tileblit *blit);
	/* cursor */
	void (*fb_tilecursor)(struct fb_info *info,
			      struct fb_tilecursor *cursor);
	/* get maximum length of the tile map */
	int (*fb_get_tilemax)(struct fb_info *info);
};
#endif /* CONFIG_FB_TILEBLITTING */

/* FBINFO_* = fb_info.flags bit flags */
#define FBINFO_HWACCEL_DISABLED	0x0002
	/* When FBINFO_HWACCEL_DISABLED is set:
	 *  Hardware acceleration is turned off.  Software implementations
	 *  of required functions (copyarea(), fillrect(), and imageblit())
	 *  takes over; acceleration engine should be in a quiescent state */

/* hints */
#define FBINFO_VIRTFB		0x0004 /* FB is System RAM, not device. */
#define FBINFO_PARTIAL_PAN_OK	0x0040 /* otw use pan only for double-buffering */
#define FBINFO_READS_FAST	0x0080 /* soft-copy faster than rendering */

/* hardware supported ops */
/*  semantics: when a bit is set, it indicates that the operation is
 *   accelerated by hardware.
 *  required functions will still work even if the bit is not set.
 *  optional functions may not even exist if the flag bit is not set.
 */
#define FBINFO_HWACCEL_NONE		0x0000
#define FBINFO_HWACCEL_COPYAREA		0x0100 /* required */
#define FBINFO_HWACCEL_FILLRECT		0x0200 /* required */
#define FBINFO_HWACCEL_IMAGEBLIT	0x0400 /* required */
#define FBINFO_HWACCEL_ROTATE		0x0800 /* optional */
#define FBINFO_HWACCEL_XPAN		0x1000 /* optional */
#define FBINFO_HWACCEL_YPAN		0x2000 /* optional */
#define FBINFO_HWACCEL_YWRAP		0x4000 /* optional */

#define FBINFO_MISC_TILEBLITTING       0x20000 /* use tile blitting */

/* A driver may set this flag to indicate that it does want a set_par to be
 * called every time when fbcon_switch is executed. The advantage is that with
 * this flag set you can really be sure that set_par is always called before
 * any of the functions dependent on the correct hardware state or altering
 * that state, even if you are using some broken X releases. The disadvantage
 * is that it introduces unwanted delays to every console switch if set_par
 * is slow. It is a good idea to try this flag in the drivers initialization
 * code whenever there is a bug report related to switching between X and the
 * framebuffer console.
 */
#define FBINFO_MISC_ALWAYS_SETPAR   0x40000

/*
 * Host and GPU endianness differ.
 */
#define FBINFO_FOREIGN_ENDIAN	0x100000
/*
 * Big endian math. This is the same flags as above, but with different
 * meaning, it is set by the fb subsystem depending FOREIGN_ENDIAN flag
 * and host endianness. Drivers should not use this flag.
 */
#define FBINFO_BE_MATH  0x100000
/*
 * Hide smem_start in the FBIOGET_FSCREENINFO IOCTL. This is used by modern DRM
 * drivers to stop userspace from trying to share buffers behind the kernel's
 * back. Instead dma-buf based buffer sharing should be used.
 */
#define FBINFO_HIDE_SMEM_START  0x200000


struct fb_info {
	refcount_t count;
	int node;/*fb设备编号*/
	int flags;
	/*
	 * -1 by default, set to a FB_ROTATE_* value by the driver, if it knows
	 * a lcd is not mounted upright and fbcon should rotate to compensate.
	 */
	int fbcon_rotate_hint;
	struct mutex lock;		/* Lock for open/release/ioctl funcs */
	struct mutex mm_lock;		/* Lock for fb_mmap and smem_* fields */
	struct fb_var_screeninfo var;	/* Current var */
	struct fb_fix_screeninfo fix;	/* Current fix */
	struct fb_monspecs monspecs;	/* Current Monitor specs */
	struct fb_pixmap pixmap;	/* Image hardware mapper */
	struct fb_pixmap sprite;	/* Cursor hardware mapper */
	struct fb_cmap cmap;		/* Current cmap */
	struct list_head modelist;      /* mode list */
	struct fb_videomode *mode;	/* current mode */

#if IS_ENABLED(CONFIG_FB_BACKLIGHT)
	/* assigned backlight device */
	/* set before framebuffer registration,
	   remove after unregister */
	struct backlight_device *bl_dev;

	/* Backlight level curve */
	struct mutex bl_curve_mutex;
	u8 bl_curve[FB_BACKLIGHT_LEVELS];
#endif
#ifdef CONFIG_FB_DEFERRED_IO
	struct delayed_work deferred_work;
	unsigned long npagerefs;
	struct fb_deferred_io_pageref *pagerefs;
	struct fb_deferred_io *fbdefio;
#endif

	const struct fb_ops *fbops;
	struct device *device;		/* This is the parent */
#if defined(CONFIG_FB_DEVICE)
	struct device *dev;		/* This is this fb device */
#endif
	int class_flag;                    /* private sysfs flags */
#ifdef CONFIG_FB_TILEBLITTING
	struct fb_tile_ops *tileops;    /* Tile Blitting */
#endif
	union {
		char __iomem *screen_base;	/* Virtual address */
		char *screen_buffer;
	};
	unsigned long screen_size;	/* Amount of ioremapped VRAM or 0 */
	void *pseudo_palette;		/* Fake palette of 16 colors */
#define FBINFO_STATE_RUNNING	0
#define FBINFO_STATE_SUSPENDED	1
	u32 state;			/* Hardware state i.e suspend */
	void *fbcon_par;                /* fbcon use-only private area */
	/* From here on everything is device dependent */
	void *par;

	bool skip_vt_switch; /* no VT switch on suspend/resume required */
};

/* This will go away
 * fbset currently hacks in FB_ACCELF_TEXT into var.accel_flags
 * when it wants to turn the acceleration engine on.  This is
 * really a separate operation, and should be modified via sysfs.
 *  But for now, we leave it broken with the following define
 */
#define STUPID_ACCELF_TEXT_SHIT

#define FB_LEFT_POS(p, bpp)          (fb_be_math(p) ? (32 - (bpp)) : 0)
#define FB_SHIFT_HIGH(p, val, bits)  (fb_be_math(p) ? (val) >> (bits) : \
						      (val) << (bits))
#define FB_SHIFT_LOW(p, val, bits)   (fb_be_math(p) ? (val) << (bits) : \
						      (val) >> (bits))

    /*
     *  `Generic' versions of the frame buffer device operations
     */

extern int fb_set_var(struct fb_info *info, struct fb_var_screeninfo *var);
extern int fb_pan_display(struct fb_info *info, struct fb_var_screeninfo *var);
extern int fb_blank(struct fb_info *info, int blank);

/*
 * Helpers for framebuffers in I/O memory
 */

extern void cfb_fillrect(struct fb_info *info, const struct fb_fillrect *rect);
extern void cfb_copyarea(struct fb_info *info, const struct fb_copyarea *area);
extern void cfb_imageblit(struct fb_info *info, const struct fb_image *image);
extern ssize_t fb_io_read(struct fb_info *info, char __user *buf,
			  size_t count, loff_t *ppos);
extern ssize_t fb_io_write(struct fb_info *info, const char __user *buf,
			   size_t count, loff_t *ppos);
int fb_io_mmap(struct fb_info *info, struct vm_area_struct *vma);

#define __FB_DEFAULT_IOMEM_OPS_RDWR \
	.fb_read	= fb_io_read, \
	.fb_write	= fb_io_write

#define __FB_DEFAULT_IOMEM_OPS_DRAW \
	.fb_fillrect	= cfb_fillrect, \
	.fb_copyarea	= cfb_copyarea, \
	.fb_imageblit	= cfb_imageblit

#define __FB_DEFAULT_IOMEM_OPS_MMAP \
	.fb_mmap	= fb_io_mmap

#define FB_DEFAULT_IOMEM_OPS \
	__FB_DEFAULT_IOMEM_OPS_RDWR, \
	__FB_DEFAULT_IOMEM_OPS_DRAW, \
	__FB_DEFAULT_IOMEM_OPS_MMAP

/*
 * Helpers for framebuffers in system memory
 */

extern void sys_fillrect(struct fb_info *info, const struct fb_fillrect *rect);
extern void sys_copyarea(struct fb_info *info, const struct fb_copyarea *area);
extern void sys_imageblit(struct fb_info *info, const struct fb_image *image);
extern ssize_t fb_sys_read(struct fb_info *info, char __user *buf,
			   size_t count, loff_t *ppos);
extern ssize_t fb_sys_write(struct fb_info *info, const char __user *buf,
			    size_t count, loff_t *ppos);

#define __FB_DEFAULT_SYSMEM_OPS_RDWR \
	.fb_read	= fb_sys_read, \
	.fb_write	= fb_sys_write

#define __FB_DEFAULT_SYSMEM_OPS_DRAW \
	.fb_fillrect	= sys_fillrect, \
	.fb_copyarea	= sys_copyarea, \
	.fb_imageblit	= sys_imageblit

/*
 * Helpers for framebuffers in DMA-able memory
 */

#define __FB_DEFAULT_DMAMEM_OPS_RDWR \
	.fb_read	= fb_sys_read, \
	.fb_write	= fb_sys_write

#define __FB_DEFAULT_DMAMEM_OPS_DRAW \
	.fb_fillrect	= sys_fillrect, \
	.fb_copyarea	= sys_copyarea, \
	.fb_imageblit	= sys_imageblit

/* fbmem.c */
extern int register_framebuffer(struct fb_info *fb_info);
extern void unregister_framebuffer(struct fb_info *fb_info);
extern char* fb_get_buffer_offset(struct fb_info *info, struct fb_pixmap *buf, u32 size);
extern void fb_pad_unaligned_buffer(u8 *dst, u32 d_pitch, u8 *src, u32 idx,
				u32 height, u32 shift_high, u32 shift_low, u32 mod);
extern void fb_pad_aligned_buffer(u8 *dst, u32 d_pitch, u8 *src, u32 s_pitch, u32 height);
extern void fb_set_suspend(struct fb_info *info, int state);
extern int fb_get_color_depth(struct fb_var_screeninfo *var,
			      struct fb_fix_screeninfo *fix);
extern int fb_get_options(const char *name, char **option);
extern int fb_new_modelist(struct fb_info *info);

static inline void lock_fb_info(struct fb_info *info)
{
	mutex_lock(&info->lock);
}

static inline void unlock_fb_info(struct fb_info *info)
{
	mutex_unlock(&info->lock);
}

static inline void __fb_pad_aligned_buffer(u8 *dst, u32 d_pitch,
					   u8 *src, u32 s_pitch, u32 height)
{
	u32 i, j;

	d_pitch -= s_pitch;

	for (i = height; i--; ) {
		/* s_pitch is a few bytes at the most, memcpy is suboptimal */
		for (j = 0; j < s_pitch; j++)
			*dst++ = *src++;
		dst += d_pitch;
	}
}

/* fb_defio.c */
int fb_deferred_io_mmap(struct fb_info *info, struct vm_area_struct *vma);
extern int  fb_deferred_io_init(struct fb_info *info);
extern void fb_deferred_io_open(struct fb_info *info,
				struct inode *inode,
				struct file *file);
extern void fb_deferred_io_release(struct fb_info *info);
extern void fb_deferred_io_cleanup(struct fb_info *info);
extern int fb_deferred_io_fsync(struct file *file, loff_t start,
				loff_t end, int datasync);

/*
 * Generate callbacks for deferred I/O
 */

#define __FB_GEN_DEFAULT_DEFERRED_OPS_RDWR(__prefix, __damage_range, __mode) \
	static ssize_t __prefix ## _defio_read(struct fb_info *info, char __user *buf, \
					       size_t count, loff_t *ppos) \
	{ \
		return fb_ ## __mode ## _read(info, buf, count, ppos); \
	} \
	static ssize_t __prefix ## _defio_write(struct fb_info *info, const char __user *buf, \
						size_t count, loff_t *ppos) \
	{ \
		unsigned long offset = *ppos; \
		ssize_t ret = fb_ ## __mode ## _write(info, buf, count, ppos); \
		if (ret > 0) \
			__damage_range(info, offset, ret); \
		return ret; \
	}

#define __FB_GEN_DEFAULT_DEFERRED_OPS_DRAW(__prefix, __damage_area, __mode) \
	static void __prefix ## _defio_fillrect(struct fb_info *info, \
						const struct fb_fillrect *rect) \
	{ \
		__mode ## _fillrect(info, rect); \
		__damage_area(info, rect->dx, rect->dy, rect->width, rect->height); \
	} \
	static void __prefix ## _defio_copyarea(struct fb_info *info, \
						const struct fb_copyarea *area) \
	{ \
		__mode ## _copyarea(info, area); \
		__damage_area(info, area->dx, area->dy, area->width, area->height); \
	} \
	static void __prefix ## _defio_imageblit(struct fb_info *info, \
						 const struct fb_image *image) \
	{ \
		__mode ## _imageblit(info, image); \
		__damage_area(info, image->dx, image->dy, image->width, image->height); \
	}

#define FB_GEN_DEFAULT_DEFERRED_IOMEM_OPS(__prefix, __damage_range, __damage_area) \
	__FB_GEN_DEFAULT_DEFERRED_OPS_RDWR(__prefix, __damage_range, io) \
	__FB_GEN_DEFAULT_DEFERRED_OPS_DRAW(__prefix, __damage_area, cfb)

#define FB_GEN_DEFAULT_DEFERRED_SYSMEM_OPS(__prefix, __damage_range, __damage_area) \
	__FB_GEN_DEFAULT_DEFERRED_OPS_RDWR(__prefix, __damage_range, sys) \
	__FB_GEN_DEFAULT_DEFERRED_OPS_DRAW(__prefix, __damage_area, sys)

/*
 * Initializes struct fb_ops for deferred I/O.
 */

#define __FB_DEFAULT_DEFERRED_OPS_RDWR(__prefix) \
	.fb_read	= __prefix ## _defio_read, \
	.fb_write	= __prefix ## _defio_write

#define __FB_DEFAULT_DEFERRED_OPS_DRAW(__prefix) \
	.fb_fillrect	= __prefix ## _defio_fillrect, \
	.fb_copyarea	= __prefix ## _defio_copyarea, \
	.fb_imageblit	= __prefix ## _defio_imageblit

#define __FB_DEFAULT_DEFERRED_OPS_MMAP(__prefix) \
	.fb_mmap	= fb_deferred_io_mmap

#define FB_DEFAULT_DEFERRED_OPS(__prefix) \
	__FB_DEFAULT_DEFERRED_OPS_RDWR(__prefix), \
	__FB_DEFAULT_DEFERRED_OPS_DRAW(__prefix), \
	__FB_DEFAULT_DEFERRED_OPS_MMAP(__prefix)

static inline bool fb_be_math(struct fb_info *info)
{
#ifdef CONFIG_FB_FOREIGN_ENDIAN
#if defined(CONFIG_FB_BOTH_ENDIAN)
	return info->flags & FBINFO_BE_MATH;
#elif defined(CONFIG_FB_BIG_ENDIAN)
	return true;
#elif defined(CONFIG_FB_LITTLE_ENDIAN)
	return false;
#endif /* CONFIG_FB_BOTH_ENDIAN */
#else
#ifdef __BIG_ENDIAN
	return true;
#else
	return false;
#endif /* __BIG_ENDIAN */
#endif /* CONFIG_FB_FOREIGN_ENDIAN */
}

extern struct fb_info *framebuffer_alloc(size_t size, struct device *dev);
extern void framebuffer_release(struct fb_info *info);
extern void fb_bl_default_curve(struct fb_info *fb_info, u8 off, u8 min, u8 max);

/* fbmon.c */
#define FB_MAXTIMINGS		0
#define FB_VSYNCTIMINGS		1
#define FB_HSYNCTIMINGS		2
#define FB_DCLKTIMINGS		3
#define FB_IGNOREMON		0x100

#define FB_MODE_IS_UNKNOWN	0
#define FB_MODE_IS_DETAILED	1
#define FB_MODE_IS_STANDARD	2
#define FB_MODE_IS_VESA		4
#define FB_MODE_IS_CALCULATED	8
#define FB_MODE_IS_FIRST	16
#define FB_MODE_IS_FROM_VAR     32

extern int fbmon_dpms(const struct fb_info *fb_info);
extern int fb_get_mode(int flags, u32 val, struct fb_var_screeninfo *var,
		       struct fb_info *info);
extern int fb_validate_mode(const struct fb_var_screeninfo *var,
			    struct fb_info *info);
extern int fb_parse_edid(unsigned char *edid, struct fb_var_screeninfo *var);
extern const unsigned char *fb_firmware_edid(struct device *device);
extern void fb_edid_to_monspecs(unsigned char *edid,
				struct fb_monspecs *specs);
extern void fb_destroy_modedb(struct fb_videomode *modedb);
extern int fb_find_mode_cvt(struct fb_videomode *mode, int margins, int rb);
extern unsigned char *fb_ddc_read(struct i2c_adapter *adapter);

extern int of_get_fb_videomode(struct device_node *np,
			       struct fb_videomode *fb,
			       int index);
extern int fb_videomode_from_videomode(const struct videomode *vm,
				       struct fb_videomode *fbmode);

/* modedb.c */
#define VESA_MODEDB_SIZE 43
#define DMT_SIZE 0x50

extern void fb_var_to_videomode(struct fb_videomode *mode,
				const struct fb_var_screeninfo *var);
extern void fb_videomode_to_var(struct fb_var_screeninfo *var,
				const struct fb_videomode *mode);
extern int fb_mode_is_equal(const struct fb_videomode *mode1,
			    const struct fb_videomode *mode2);
extern int fb_add_videomode(const struct fb_videomode *mode,
			    struct list_head *head);
extern void fb_delete_videomode(const struct fb_videomode *mode,
				struct list_head *head);
extern const struct fb_videomode *fb_match_mode(const struct fb_var_screeninfo *var,
						struct list_head *head);
extern const struct fb_videomode *fb_find_best_mode(const struct fb_var_screeninfo *var,
						    struct list_head *head);
extern const struct fb_videomode *fb_find_nearest_mode(const struct fb_videomode *mode,
						       struct list_head *head);
extern void fb_destroy_modelist(struct list_head *head);
extern void fb_videomode_to_modelist(const struct fb_videomode *modedb, int num,
				     struct list_head *head);
extern const struct fb_videomode *fb_find_best_display(const struct fb_monspecs *specs,
						       struct list_head *head);

/* fbcmap.c */
extern int fb_alloc_cmap(struct fb_cmap *cmap, int len, int transp);
extern int fb_alloc_cmap_gfp(struct fb_cmap *cmap, int len, int transp, gfp_t flags);
extern void fb_dealloc_cmap(struct fb_cmap *cmap);
extern int fb_copy_cmap(const struct fb_cmap *from, struct fb_cmap *to);
extern int fb_cmap_to_user(const struct fb_cmap *from, struct fb_cmap_user *to);
extern int fb_set_cmap(struct fb_cmap *cmap, struct fb_info *fb_info);
extern int fb_set_user_cmap(struct fb_cmap_user *cmap, struct fb_info *fb_info);
extern const struct fb_cmap *fb_default_cmap(int len);
extern void fb_invert_cmaps(void);

struct fb_videomode {
	const char *name;	/* optional */
	u32 refresh;		/* optional */
	u32 xres;
	u32 yres;
	u32 pixclock;
	u32 left_margin;
	u32 right_margin;
	u32 upper_margin;
	u32 lower_margin;
	u32 hsync_len;
	u32 vsync_len;
	u32 sync;
	u32 vmode;
	u32 flag;
};

struct dmt_videomode {
	u32 dmt_id;
	u32 std_2byte_code;
	u32 cvt_3byte_code;
	const struct fb_videomode *mode;
};

extern const struct fb_videomode vesa_modes[];
extern const struct dmt_videomode dmt_modes[];

struct fb_modelist {
	struct list_head list;
	struct fb_videomode mode;
};

extern int fb_find_mode(struct fb_var_screeninfo *var,
			struct fb_info *info, const char *mode_option,
			const struct fb_videomode *db,
			unsigned int dbsize,
			const struct fb_videomode *default_mode,
			unsigned int default_bpp);

#if defined(CONFIG_VIDEO_NOMODESET)
bool fb_modesetting_disabled(const char *drvname);
#else
static inline bool fb_modesetting_disabled(const char *drvname)
{
	return false;
}
#endif

/*
 * Convenience logging macros
 */

#define fb_err(fb_info, fmt, ...)					\
	pr_err("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_notice(info, fmt, ...)					\
	pr_notice("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_warn(fb_info, fmt, ...)					\
	pr_warn("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_info(fb_info, fmt, ...)					\
	pr_info("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_dbg(fb_info, fmt, ...)					\
	pr_debug("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)

#define fb_warn_once(fb_info, fmt, ...)					\
	pr_warn_once("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)

#define fb_WARN_ONCE(fb_info, condition, fmt, ...) \
	WARN_ONCE(condition, "fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_WARN_ON_ONCE(fb_info, x) \
	fb_WARN_ONCE(fb_info, (x), "%s", "fb_WARN_ON_ONCE(" __stringify(x) ")")

#endif /* _LINUX_FB_H */
