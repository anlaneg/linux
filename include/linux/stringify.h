#ifndef __LINUX_STRINGIFY_H
#define __LINUX_STRINGIFY_H

/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */

#define __stringify_1(x...)	#x

/*将参数x...格式化为字符串*/
#define __stringify(x...)	__stringify_1(x)

#define FILE_LINE	__FILE__ ":" __stringify(__LINE__)

#endif	/* !__LINUX_STRINGIFY_H */
