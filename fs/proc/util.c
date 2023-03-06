#include <linux/dcache.h>
#include "internal.h"

unsigned name_to_int(const struct qstr *qstr)
{
	const char *name = qstr->name;
	int len = qstr->len;
	unsigned n = 0;

	if (len > 1 && *name == '0')
		/*以'0'开头，认为非数字*/
		goto out;
	do {
		unsigned c = *name++ - '0';
		if (c > 9)
			/*遇到非数字*/
			goto out;
		if (n >= (~0U-9)/10)
			/*n会绕回或者近乎绕回，认为非数字*/
			goto out;
		/*完成转换*/
		n *= 10;
		n += c;
	} while (--len > 0);
	/*返回转换后的数字*/
	return n;
out:
	return ~0U;
}
