/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __SOUND_MINORS_H
#define __SOUND_MINORS_H

/*
 *  MINOR numbers
 */

#define SNDRV_OS_MINORS			256

#define SNDRV_MINOR_DEVICES		32
#define SNDRV_MINOR_CARD(minor)		((minor) >> 5)
#define SNDRV_MINOR_DEVICE(minor)	((minor) & 0x001f)
#define SNDRV_MINOR(card, dev)		(((card) << 5) | (dev))

/* these minors can still be used for autoloading devices (/dev/aload*) */
#define SNDRV_MINOR_CONTROL		0	/* 0 */
#define SNDRV_MINOR_GLOBAL		1	/* 1 */
#define SNDRV_MINOR_SEQUENCER		1	/* SNDRV_MINOR_GLOBAL + 0 * 32 */
#define SNDRV_MINOR_TIMER		33	/* SNDRV_MINOR_GLOBAL + 1 * 32 */

#ifndef CONFIG_SND_DYNAMIC_MINORS
#define SNDRV_MINOR_COMPRESS		2	/* 2 - 3 */
#define SNDRV_MINOR_HWDEP		4	/* 4 - 7 */
#define SNDRV_MINOR_RAWMIDI		8	/* 8 - 15 */
#define SNDRV_MINOR_PCM_PLAYBACK	16	/* 16 - 23 */
#define SNDRV_MINOR_PCM_CAPTURE		24	/* 24 - 31 */

/* same as first respective minor number to make minor allocation easier */
#define SNDRV_DEVICE_TYPE_CONTROL	SNDRV_MINOR_CONTROL
#define SNDRV_DEVICE_TYPE_HWDEP		SNDRV_MINOR_HWDEP
#define SNDRV_DEVICE_TYPE_RAWMIDI	SNDRV_MINOR_RAWMIDI
#define SNDRV_DEVICE_TYPE_PCM_PLAYBACK	SNDRV_MINOR_PCM_PLAYBACK
#define SNDRV_DEVICE_TYPE_PCM_CAPTURE	SNDRV_MINOR_PCM_CAPTURE
#define SNDRV_DEVICE_TYPE_SEQUENCER	SNDRV_MINOR_SEQUENCER
#define SNDRV_DEVICE_TYPE_TIMER		SNDRV_MINOR_TIMER
#define SNDRV_DEVICE_TYPE_COMPRESS	SNDRV_MINOR_COMPRESS

#else /* CONFIG_SND_DYNAMIC_MINORS */

enum {
	/*作用：负责音量调节、静音开关、输入源切换（如选择麦克风或线路输入）、通道路由等*/
	SNDRV_DEVICE_TYPE_CONTROL,
	/*主要处理 MIDI（乐器数字接口）事件和时序控制。*/
	SNDRV_DEVICE_TYPE_SEQUENCER,
	/*作用：为音频事件提供精确的时间戳和同步。*/
	SNDRV_DEVICE_TYPE_TIMER,
	/*作用：为特定硬件提供“后门”，处理那些不属于通用规范的私有功能。*/
	SNDRV_DEVICE_TYPE_HWDEP,
	/*作用：处理电子乐器（键盘、合成器）的 MIDI 协议数据。*/
	SNDRV_DEVICE_TYPE_RAWMIDI,
	/*处理数字音频采样数据，即真正的“声音”流。*/
	SNDRV_DEVICE_TYPE_PCM_PLAYBACK,/*pcm播放*/
	SNDRV_DEVICE_TYPE_PCM_CAPTURE,/*pcm录制*/
	/*作用：处理硬件解码的压缩音频流（如 MP3, AAC, AC3）。*/
	SNDRV_DEVICE_TYPE_COMPRESS,
};

#endif /* CONFIG_SND_DYNAMIC_MINORS */

#define SNDRV_MINOR_HWDEPS		4
#define SNDRV_MINOR_RAWMIDIS		8
#define SNDRV_MINOR_PCMS		8


#ifdef CONFIG_SND_OSSEMUL

#define SNDRV_MINOR_OSS_DEVICES		16
#define SNDRV_MINOR_OSS_CARD(minor)	((minor) >> 4)
#define SNDRV_MINOR_OSS_DEVICE(minor)	((minor) & 0x000f)
#define SNDRV_MINOR_OSS(card, dev)	(((card) << 4) | (dev))

#define SNDRV_MINOR_OSS_MIXER		0	/* /dev/mixer - OSS 3.XX compatible */
#define SNDRV_MINOR_OSS_SEQUENCER	1	/* /dev/sequencer - OSS 3.XX compatible */
#define	SNDRV_MINOR_OSS_MIDI		2	/* /dev/midi - native midi interface - OSS 3.XX compatible - UART */
#define SNDRV_MINOR_OSS_PCM		3	/* alias */
#define SNDRV_MINOR_OSS_PCM_8		3	/* /dev/dsp - 8bit PCM - OSS 3.XX compatible */
#define SNDRV_MINOR_OSS_AUDIO		4	/* /dev/audio - SunSparc compatible */
#define SNDRV_MINOR_OSS_PCM_16		5	/* /dev/dsp16 - 16bit PCM - OSS 3.XX compatible */
#define SNDRV_MINOR_OSS_SNDSTAT		6	/* /dev/sndstat - for compatibility with OSS */
#define SNDRV_MINOR_OSS_RESERVED7	7	/* reserved for future use */
#define SNDRV_MINOR_OSS_MUSIC		8	/* /dev/music - OSS 3.XX compatible */
#define SNDRV_MINOR_OSS_DMMIDI		9	/* /dev/dmmidi0 - this device can have another minor # with OSS */
#define SNDRV_MINOR_OSS_DMFM		10	/* /dev/dmfm0 - this device can have another minor # with OSS */
#define SNDRV_MINOR_OSS_MIXER1		11	/* alternate mixer */
#define SNDRV_MINOR_OSS_PCM1		12	/* alternate PCM (GF-A-1) */
#define SNDRV_MINOR_OSS_MIDI1		13	/* alternate midi - SYNTH */
#define SNDRV_MINOR_OSS_DMMIDI1		14	/* alternate dmmidi - SYNTH */
#define SNDRV_MINOR_OSS_RESERVED15	15	/* reserved for future use */

#define SNDRV_OSS_DEVICE_TYPE_MIXER	0
#define SNDRV_OSS_DEVICE_TYPE_SEQUENCER	1
#define SNDRV_OSS_DEVICE_TYPE_PCM	2
#define SNDRV_OSS_DEVICE_TYPE_MIDI	3
#define SNDRV_OSS_DEVICE_TYPE_DMFM	4
#define SNDRV_OSS_DEVICE_TYPE_SNDSTAT	5
#define SNDRV_OSS_DEVICE_TYPE_MUSIC	6

#define MODULE_ALIAS_SNDRV_MINOR(type) \
	MODULE_ALIAS("sound-service-?-" __stringify(type))

#endif

#endif /* __SOUND_MINORS_H */
