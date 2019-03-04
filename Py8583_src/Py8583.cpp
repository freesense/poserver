
#include <Python.h>
#include "structmember.h"
#include <sstream>
#include <string>
#include <ctype.h>
#include <event.h>
#include <map>
#include <pthread.h>

using namespace std;

typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned char uchar;
typedef unsigned short ushort;

#define GY8583_MAX_ENTRY 64
#define max(x, y) ((x) > (y)) ? (x) :(y)
#define min(x, y) ((x) > (y)) ? (y) :(x)
#define SET_ERR(X) { \
	self->m_error_lineno = __LINE__; \
	self->m_error_msg = (X); \
}

#define ERR_RETURN(X, Y) { \
	self->m_error_lineno = __LINE__; \
	self->m_error_msg = (X); \
	return (Y); \
}

const char ERR_TOOLONG[] = "数据太长";
const char ERR_VALUE[] = "值错误";
const char ERR_BITNOTSET[] = "域未设置";

/////////////////////////////////////////////////////////////////////////////
struct GY8583_main {
    uint index;                   	//序号
    string bittype;                 //字段类型
    uint length;                  	//字段长度
    string valuetype;               //值类型
    int isbcd;                      //1 表示使用bcd压缩，0 表示不使用bcd压缩
    int align;                      //0 左补0, 1 右补0
};

struct GY8583_main GY8583_DEFINE[] = {
    {0,  "",    0,   "",    0, 0},
    {1,  "B",   16,  "b",   0, 0},
    {2,  "LL",  19,  "n",   1, 0},
    {3,  "N",   6,   "n",   1, 0},
    {4,  "N",   12,  "n",   1, 0},
    {5,  "N",   12,  "n",   0, 0},
    {6,  "N",   12,  "n",   0, 0},
    {7,  "N",   10,  "n",   0, 0},
    {8,  "N",   8,   "n",   0, 0},
    {9,  "N",   8,   "n",   0, 0},
    {10, "N",   8,   "n",   0, 0},
    {11, "N",   6,   "n",   1, 0},
    {12, "N",   6,   "n",   1, 0},
    {13, "N",   4,   "n",   1, 0},
    {14, "N",   4,   "n",   1, 0},
    {15, "N",   4,   "n",   1, 0},
    {16, "N",   4,   "n",   0, 0},
    {17, "N",   4,   "n",   0, 0},
    {18, "LLL", 4,   "n",   0, 0},
    {19, "N",   3,   "n",   0, 0},
    {20, "N",   3,   "n",   0, 0},
    {21, "ANS", 3,   "n",   0, 0},
    {22, "N",   3,   "n",   1, 1},
    {23, "N",   3,   "n",   0, 0},
    {24, "N",   3,   "n",   0, 0},
    {25, "N",   2,   "n",   1, 0},
    {26, "N",   2,   "n",   1, 0},
    {27, "N",   1,   "n",   0, 0},
    {28, "N",   8,   "n",   0, 0},
    {29, "N",   8,   "n",   0, 0},
    {30, "N",   8,   "n",   0, 0},
    {31, "N",   8,   "n",   0, 0},
    {32, "LL",  11,  "n",   1, 0},
    {33, "LL",  11,  "n",   0, 0},
    {34, "LL",  28,  "n",   0, 0},
    {35, "LL",  37,  "n",   1, 0},
    {36, "LLL", 104, "n",   0, 0},
    {37, "N",   12,  "an",  0, 0},
    {38, "N",   6,   "an",  0, 0},
    {39, "A",   2,   "an",  0, 0},
    {40, "N",   3,   "an",  0, 0},
    {41, "N",   8,   "ans", 0, 0},
    {42, "A",   15,  "ans", 0, 0},
    {43, "A",   40,  "asn", 0, 0},
    {44, "LL",  25,  "an",  0, 0},
    {45, "LL",  76,  "an",  0, 0},
    {46, "LLL", 999, "an",  0, 0},
    {47, "LLL", 999, "an",  0, 0},
    {48, "LLL", 999, "an",  1, 0},
    {49, "A",   3,   "a",   0, 0},
    {50, "AN",  3,   "an",  0, 0},
    {51, "A",   3,   "a",   0, 0},
    {52, "B",   8,   "b",   0, 0},
    {53, "N",   16,  "n",   1, 0},
    {54, "LLL", 120, "an",  0, 0},
    {55, "LLL", 999, "ans", 0, 0},
    {56, "LLL", 999, "ans", 0, 0},
    {57, "LLL", 999, "ans", 0, 0},
    {58, "LLL", 999, "ans", 0, 0},
    {59, "LLL", 999, "ans", 0, 0},
    {60, "LLL", 999, "ans", 1, 0},
    {61, "LLL", 999, "ans", 1, 0},
    {62, "LLL", 999, "ans", 0, 0},
    {63, "LLL", 999, "ans", 0, 0},
    {64, "B",   8,   "b",   0, 0}
};

/////////////////////////////////////////////////////////////////////////////
uint bcd2dec(const char *data, uint len)
{
	uint ret = 0;
    uchar tmp;
    for (uint i = 0; i < len; i++) {
        //左边4bit
        ret *= 10;
        tmp = ((uchar)data[i]) >> 4;
        if (tmp > 9) tmp += 'a' - 10;
        ret += tmp;
        ret *= 10;
        //右边4bit
        tmp = ((uchar)data[i]) & 0x0F;
        if (tmp > 9) tmp += 'a' - 10;
        ret += tmp;
    }
    return ret;
}

void bcd2str(const char *data, uint len, char *buf, uint width, bool alignLeft)
{
#define ds_to_char(x) ((x)>9?(x)-10+'A':(x)+'0')

	uchar tmp;
	int pos = 0;
	memset(buf, '0', width);

	if (!alignLeft) {
		pos = width - (len << 1);
		if (pos < 0)
			pos = 0;
	}

    for (uint i = 0; i < len; i++) {
        tmp = ((uchar)data[i]) >> 4;
        buf[pos++] = ds_to_char(tmp);
        tmp = ((uchar)data[i]) & 0x0F;
        buf[pos++] = ds_to_char(tmp);
    }
}

void dec2bcd(uint value, char *buf, uint width, bool alignLeft)
{
	uint tmp = value, pos = width;
    uchar t = 0x00;
    memset(buf, 0, width);

    while (tmp > 0) {
        t = tmp % 10;
        tmp /= 10;
        t += ((tmp % 10) << 4);
        tmp /= 10;
        buf[--pos] = t;
    }

	if (alignLeft && pos > 0)
	{
		uint fill = width - pos;
		memmove(buf, buf + pos, fill);
		memset(buf + pos, 0, fill);
	}
}

uchar __ord(uchar t)
{
	if (t >= '0' && t <= '9')
        return t - '0';
   	if (t >= 'a' && t <= 'f')
       	return t - 'a' + 10;
    if (t > 'A' && t <= 'F')
   	    return t - 'A' + 10;
    return (uchar)-1;
}

void str2bcd(const char *value, char *buf, uint width, bool alignLeft)
{
#define char2char(x, y) ((__ord(x) << 4) + __ord(y))

	memset(buf, '0', width);
	uint pos = 0, size = ((strlen(value) >> 1) << 1), i = 0;
	if (!alignLeft)
		pos = width - ((size + 1) >> 1);

	for (; i < size; i++)
        buf[pos++] = char2char(value[i], value[++i]);

	if (pos < width)
		buf[pos] = char2char(value[i], '0');
}

/////////////////////////////////////////////////////////////////////////////
static PyObject * Py8583_bcd2dec(PyObject *self, PyObject *args)
{
	const char * data = NULL;
	uint len = 0;
	if (!PyArg_ParseTuple(args, "s#", &data, &len))
		return NULL;
	uint ret = bcd2dec(data, len);
    return Py_BuildValue("I", ret);
}

static PyObject * Py8583_bcd2str(PyObject *self, PyObject *args)
{
	const char *data = NULL, *align = "left";
	uint len = 0, width = 0;
	bool alignLeft = true;
	if (!PyArg_ParseTuple(args, "s#|Is", &data, &len, &width, &align))
		return NULL;

	if (strcasecmp(align, "left"))
		alignLeft = false;
	width = max(width, (len << 1));
	char *buf = new char[width];

	bcd2str(data, len, buf, width, alignLeft);
	PyObject *ret = Py_BuildValue("s#", buf, width);
	delete []buf;

	return ret;
}

static PyObject * Py8583_dec2bcd(PyObject *self, PyObject *args)
{
	const char *align = "left";
	uint width = 0, data = 0;
	bool alignLeft = true;
	if (!PyArg_ParseTuple(args, "I|Is", &data, &width, &align))
		return NULL;

	if (strcasecmp(align, "left"))
		alignLeft = false;

	stringstream ss;
	ss << data;
	width = max(width, (ss.str().length() + 1) >> 1);
	char *buf = new char[width];

	dec2bcd(data, buf, width, alignLeft);
	PyObject *ret = Py_BuildValue("s#", buf, width);
	delete []buf;

	return ret;
}

static PyObject * Py8583_str2bcd(PyObject *self, PyObject *args)
{
	const char *align = "left", *data = NULL;
	uint width = 0;
	bool alignLeft = true;
	if (!PyArg_ParseTuple(args, "s|Is", &data, &width, &align))
		return NULL;

	if (strcasecmp(align, "left"))
		alignLeft = false;
	width = max(width, ((strlen(data) + 1) >> 1));
	char *buf = new char[width];

	str2bcd(data, buf, width, alignLeft);
	PyObject *ret = Py_BuildValue("s#", buf, width);
	delete []buf;

	return ret;
}

/////////////////////////////////////////////////////////////////////////////
typedef struct {
    PyObject_HEAD
    char *m_pData;
    uint m_nLength;
    uint m_mti;
    char m_bitmap[8];
	PyObject *m_fields;

    uint m_error_lineno;
    const char *m_error_msg;
} Py8583;

static void Py8583_dealloc(Py8583* self)
{
	Py_XDECREF(self->m_fields);
    delete []self->m_pData;
    self->m_pData = NULL;
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject * Py8583_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Py8583 *self;

    self = (Py8583 *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->m_nLength = self->m_mti = 0;
        self->m_pData = NULL;
        memset(self->m_bitmap, 0, sizeof(self->m_bitmap));

        self->m_fields = PyDict_New();
        if (self->m_fields == NULL) {
        	Py_DECREF(self);
        	return NULL;
        }
    }

    return (PyObject *)self;
}

static int Py8583_init(Py8583 *self, PyObject *args)
{
	char *lpTmp = NULL;
	if (!PyArg_ParseTuple(args, "|s#", &lpTmp, &self->m_nLength))
		return -1;

	if (self->m_nLength > 0) {
		self->m_pData = new char[self->m_nLength];
		memcpy(self->m_pData, lpTmp, self->m_nLength);
	}

    return 0;
}

int parse_domain(char const* data, uint sz, int bit, Py8583 *self)
{
	int offset = 0;
    //realsz实际需要从输入获取的长度 theorysz数据理论长度，解压之后长度应当一致
    uint realsz = 0, theorysz = 0;

    if (GY8583_DEFINE[bit].bittype[0] == 'L') {
        //变长字段,判断几个L,因为这是我们自己的定义，不用做太多的检查
        uint lengthsz = GY8583_DEFINE[bit].bittype.size();
        lengthsz = ((lengthsz + 1) >> 1);
        if (offset + lengthsz > sz) {
            //剩下的长度不足长度位
            ERR_RETURN(ERR_TOOLONG, -1);
        }
        theorysz = bcd2dec(&data[offset], lengthsz);
        offset += lengthsz;
        if (theorysz > GY8583_DEFINE[bit].length) {
            //超过定义的最大长度了,设置错误码并返回错误
            ERR_RETURN(ERR_TOOLONG, -1);
        }
    } else {
        //定长字段
        theorysz = GY8583_DEFINE[bit].length;
    }

    if (0 != GY8583_DEFINE[bit].isbcd){
        realsz = ((theorysz + 1) >> 1);
    } else {
        realsz = theorysz;
    }

    if (offset + realsz > sz) {
        //剩下数据根本不足需要的长度
        ERR_RETURN(ERR_TOOLONG, -1);
    }

    //获取实际数据，如果是bcd压缩的那么解压放到values中，否则直接拷贝过来
    if (0 == GY8583_DEFINE[bit].isbcd) {
    	PyObject *key = PyInt_FromLong(bit);
    	PyObject *value = PyString_FromStringAndSize(&data[offset], realsz);
    	if (-1 == PyDict_SetItem(self->m_fields, key, value)) {
    		Py_DECREF(key);
    		Py_DECREF(value);
    		ERR_RETURN(ERR_VALUE, -1);
    	}
    	Py_DECREF(key);
    	Py_DECREF(value);
    } else {
    	char *buf = new char[theorysz];
    	bcd2str(&data[offset], realsz, buf, theorysz, GY8583_DEFINE[bit].align == 0 ? false : true);
    	PyObject *key = PyInt_FromLong(bit);
    	PyObject *value = PyString_FromStringAndSize(buf, theorysz);
    	if (-1 == PyDict_SetItem(self->m_fields, key, value)) {
    		Py_DECREF(key);
    		Py_DECREF(value);
    		ERR_RETURN(ERR_VALUE, -1);
    	}
    	Py_DECREF(key);
    	Py_DECREF(value);
    	delete []buf;
    }

    return offset + realsz;
}

static PyObject * Py8583_parse(Py8583 *self, PyObject *args)
{
	char *lpTmp = NULL;
	uint len = 0;
	PyDict_Clear(self->m_fields);
	if (!PyArg_ParseTuple(args, "|s#", &lpTmp, &len))
		return NULL;

	if (len > 0) {
		delete []self->m_pData;
		self->m_pData = (char*)malloc(len);
		memcpy(self->m_pData, lpTmp, len);
		self->m_nLength = len;
	}

	if (self->m_pData == NULL) {
		PyErr_SetString(PyExc_ValueError, "需要解析的8583数据为空");
		return NULL;
	}

	if (self->m_nLength < 2 + sizeof(self->m_bitmap)) {
		stringstream ss;
        ss << ERR_TOOLONG << "[" << 111 << "]";
		PyErr_SetString(PyExc_ValueError, ss.str().c_str());
		return NULL;
	}

	self->m_mti = bcd2dec(self->m_pData, 2);
	memcpy(self->m_bitmap, &self->m_pData[2], sizeof(self->m_bitmap));
	uint offset = 2 + sizeof(self->m_bitmap);

	for (uint i = 0; i < GY8583_MAX_ENTRY; )
	{
		uchar c = self->m_bitmap[(i / 8)];
		for (uint j = 0; j < 8; j++, i++) {
            if (c & 0x80) {
                int ret = parse_domain(&self->m_pData[offset], self->m_nLength - offset, i+1, self);
                if (-1 == ret) {
                	stringstream ss;
                	ss << self->m_error_msg << "[" << self->m_error_lineno << "]";
                    PyErr_SetString(PyExc_ValueError, ss.str().c_str());
                    return NULL;
                }
                offset += ret;
            }
            c <<= 1;
        }
	}
	return PyBool_FromLong(1);
}

static PyObject * Py8583_getBit(Py8583 *self, PyObject *args)
{
	uint bit = 0;
	if (!PyArg_ParseTuple(args, "I", &bit))
		return NULL;

	PyObject *pyBit = PyInt_FromLong(bit);
	PyObject *value = PyDict_GetItem(self->m_fields, pyBit);
	if (value == NULL) {
		Py_DECREF(pyBit);
		PyErr_SetString(PyExc_ValueError, ERR_BITNOTSET);
		return NULL;
	}
	Py_INCREF(value);
	Py_DECREF(pyBit);
	return value;
}

static PyObject * Py8583_getBitNext(Py8583 *self, PyObject *args)
{
	uint bit = 0, pos = 0, width = 0;
	const char *type = NULL;
	if (!PyArg_ParseTuple(args, "II(sI)", &bit, &pos, &type, &width))
		return NULL;

	PyObject *pyBit = PyInt_FromLong(bit);
	PyObject *value = PyDict_GetItem(self->m_fields, pyBit);
	if (value == NULL) {
		Py_DECREF(pyBit);
		PyErr_SetString(PyExc_ValueError, ERR_BITNOTSET);
		return NULL;
	}

	char *buf = NULL;
	Py_ssize_t length = 0;
	int dd = PyString_AsStringAndSize(value, &buf, &length);

	uint len = width;
	if (tolower(type[0]) == 'l') {
		uint _len = (strlen(type) + 1) >> 1;
		len = bcd2dec(buf + pos, _len);
		pos += _len;
	}

	if (len > width) {
		PyErr_SetString(PyExc_ValueError, ERR_TOOLONG);
		return NULL;
	}

	return Py_BuildValue("(I, s#)", pos + len, buf + pos, len);
}

static PyObject * Py8583_getRawIso(Py8583 *self)
{
	stringstream ss;
	char bcd[2];
	dec2bcd(self->m_mti, bcd, 2, true);
	ss.write(bcd, sizeof(bcd));
    ss.write(self->m_bitmap, sizeof(self->m_bitmap));

    PyObject * keys = PyDict_Keys(self->m_fields);
	PyList_Sort(keys);
	for (Py_ssize_t i = 0; i < PyList_GET_SIZE(keys); i++) {
		PyObject * key = PyList_GetItem(keys, i);
		uint idx = PyInt_AsLong(key);
		PyObject * value = PyDict_GetItem(self->m_fields, key);
		char *buf = NULL;
		Py_ssize_t length = 0;
		int dd = PyString_AsStringAndSize(value, &buf, &length);

		//如果是变长需要写入则需要先写数据长度部分
		if ('L' == GY8583_DEFINE[idx].bittype[0]) {
            uint lensz = ((GY8583_DEFINE[idx].bittype.length()+1) >> 1);
            dec2bcd(length, bcd, lensz, false);		//长度域右对齐
            ss.write(bcd, lensz);
        }

        //写数据，需要判断是否BCD压缩
        if (GY8583_DEFINE[idx].isbcd) {
        	uint width = ((length + 1) >> 1);
        	char *_d = new char[width];
        	str2bcd(buf, _d, width, true);
        	ss.write(_d, width);
        	delete []_d;
        } else {
        	ss.write(buf, length);
        }
	}
	Py_DECREF(keys);

	string s = ss.str();
	delete []self->m_pData;
	self->m_nLength = s.length();
	self->m_pData = new char[s.length()];
	memcpy(self->m_pData, s.data(), s.length());
	return Py_BuildValue("s#", self->m_pData, self->m_nLength);
}

static PyObject * Py8583_addBit(Py8583 *self, PyObject *args)
{
	const char * data = NULL, *type = NULL;
	uint bit = 0, length = 0, width = 0;
	if (!PyArg_ParseTuple(args, "I(sIs#)", &bit, &type, &width, &data, &length))
		return NULL;

	if (bit > GY8583_MAX_ENTRY || length > GY8583_DEFINE[bit].length) {
		PyErr_SetString(PyExc_ValueError, ERR_VALUE);
		return NULL;
	}

	PyObject * append_str = NULL;
	PyObject * key = PyInt_FromLong(bit);
	PyObject * value = PyDict_GetItem(self->m_fields, key);

	if (type[0] == 'L') {
		char *pTmp = NULL;
		uint pos = (strlen(type) >> 1);
		uint total_length = pos + length;
		pTmp = new char[total_length];
		dec2bcd(length, pTmp, pos, false);
		memcpy(pTmp + pos, data, length);
		append_str = PyString_FromStringAndSize(pTmp, total_length);
		delete []pTmp;
	} else if (width == length) {
		append_str = PyString_FromStringAndSize(data, length);
	} else if (GY8583_DEFINE[bit].align == 0) {		//左补0
		char *tmp = new char[width];
		memset(tmp, '0', width);
		memcpy(tmp + width - length, data, length);
		append_str = PyString_FromStringAndSize(tmp, width);
		delete []tmp;
	} else {		//右补0
		char *tmp = new char[width];
		memset(tmp, '0', width);
		memcpy(tmp, data, length);
		append_str = PyString_FromStringAndSize(tmp, width);
		delete []tmp;
	}

	if (value == NULL) {
		if (bit % 8 == 0)
			self->m_bitmap[bit / 8 - 1] |= 1;
		else
			self->m_bitmap[bit / 8] |= (1 << (8 - (bit % 8)));
		PyDict_SetItem(self->m_fields, key, append_str);
	} else {
		Py_INCREF(value);
		PyString_Concat(&value, append_str);
		PyDict_SetItem(self->m_fields, key, value);
		Py_DECREF(value);
	}

	Py_DECREF(key);
	Py_DECREF(append_str);
	Py_RETURN_NONE;
}

static PyObject * Py8583_setBit(Py8583 *self, PyObject *args)
{
	const char * data = NULL;
	uint bit = 0, length = 0;
	if (!PyArg_ParseTuple(args, "Is#", &bit, &data, &length))
		return NULL;

	if (bit > GY8583_MAX_ENTRY || length > GY8583_DEFINE[bit].length) {
		PyErr_SetString(PyExc_ValueError, ERR_VALUE);
		return NULL;
	}

	PyObject * key = PyInt_FromLong(bit);
	PyObject * value = NULL;
	int zfill = GY8583_DEFINE[bit].length - length;
	if (zfill == 0)
		value = PyString_FromStringAndSize(data, length);
	else if (GY8583_DEFINE[bit].bittype[0] == 'L')	//变长字段
        value = PyString_FromStringAndSize(data, length);
	else if (GY8583_DEFINE[bit].align == 0) {		//左补0
		char *tmp = new char[GY8583_DEFINE[bit].length];
		memset(tmp, '0', GY8583_DEFINE[bit].length);
		memcpy(tmp + zfill, data, length);
		value = PyString_FromStringAndSize(tmp, GY8583_DEFINE[bit].length);
		delete []tmp;
	} else {		//右补0
		char *tmp = new char[GY8583_DEFINE[bit].length];
		memset(tmp, '0', GY8583_DEFINE[bit].length);
		memcpy(tmp, data, length);
		value = PyString_FromStringAndSize(tmp, GY8583_DEFINE[bit].length);
		delete []tmp;
	}

	if (bit % 8 == 0)
		self->m_bitmap[bit / 8 - 1] |= 1;
	else
		self->m_bitmap[bit / 8] |= (1 << (8 - (bit % 8)));

	PyDict_SetItem(self->m_fields, key, value);
	Py_DECREF(key);
	Py_DECREF(value);
	Py_RETURN_NONE;
}

static PyObject * Py8583_getMTI(Py8583 *self, void *closure)
{
    return PyInt_FromLong(self->m_mti);
}

static int Py8583_setMTI(Py8583 *self, PyObject *value, void *closure)
{
	if (value == NULL || !PyInt_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "参数错误");
		return -1;
	}

	self->m_mti = PyInt_AsLong(value);
	return 0;
}

static PyObject * Py8583_repr(Py8583 * self)
{
	return Py8583_getRawIso(self);
}

static PyObject * Py8583_str(Py8583 * self)
{
	stringstream ss;
	ss << "Raw length = " << self->m_nLength << endl;
	ss << "MTI: " << self->m_mti << endl;

	PyObject * keys = PyDict_Keys(self->m_fields);
	PyList_Sort(keys);
	for (Py_ssize_t i = 0; i < PyList_GET_SIZE(keys); i++) {
		PyObject * key = PyList_GetItem(keys, i);
		PyObject * value = PyDict_GetItem(self->m_fields, key);
		char *buf = NULL;
		Py_ssize_t length = 0;
		int dd = PyString_AsStringAndSize(value, &buf, &length);
		ss << "Bit[" << PyInt_AS_LONG(key) << "]: " << string(buf, length) << endl;
	}

	Py_DECREF(keys);
	string s = ss.str();
    return PyString_FromStringAndSize(s.data(), s.length());
}

static PyMemberDef Py8583_members[] = {
//    {"first", T_OBJECT_EX, offsetof(Py8583, first), 0, "first name"},
//    {"last", T_OBJECT_EX, offsetof(Py8583, last), 0, "last name"},
//    {"mti", T_INT, offsetof(Py8583, number), 0, "noddy number"},
    {NULL}  /* Sentinel */
};

static PyGetSetDef Py8583_getseters[] = {
    {"mti", (getter)Py8583_getMTI, (setter)Py8583_setMTI, "8583包业务类型", NULL},
//    {"last", (getter)Py8583_getlast, (setter)Py8583_setlast, "last name", NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef Py8583_methods[] = {
	{"parse", (PyCFunction)Py8583_parse, METH_VARARGS, "解析8583数据包"},
	{"getBit", (PyCFunction)Py8583_getBit, METH_VARARGS, "获得8583域的值"},
	{"getBitNext", (PyCFunction)Py8583_getBitNext, METH_VARARGS, "获得8583子域的值"},
	{"setBit", (PyCFunction)Py8583_setBit, METH_VARARGS, "设置8583域的值"},
	{"addBit", (PyCFunction)Py8583_addBit, METH_VARARGS, "向8583的域添加值"},
	{"getRawIso", (PyCFunction)Py8583_getRawIso, METH_NOARGS, "设置8583域的复合子值"},
    {NULL}  /* Sentinel */
};

static PyTypeObject Py8583Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         	/*ob_size*/
    "Py8583.Py8583",             	/*tp_name*/
    sizeof(Py8583), 				/*tp_basicsize*/
    0,                         	/*tp_itemsize*/
    (destructor)Py8583_dealloc,                         	/*tp_dealloc*/
    0,                         	/*tp_print*/
    0,                         	/*tp_getattr*/
    0,                         	/*tp_setattr*/
    0,                         	/*tp_compare*/
    (reprfunc)Py8583_repr,                         	/*tp_repr*/
    0,                         	/*tp_as_number*/
    0,                         	/*tp_as_sequence*/
    0,                         	/*tp_as_mapping*/
    0,                         	/*tp_hash */
    0,                         	/*tp_call*/
    (reprfunc)Py8583_str,                         	/*tp_str*/
    0,                         	/*tp_getattro*/
    0,                         	/*tp_setattro*/
    0,                         	/*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        	/*tp_flags*/
    "Py8583 objects",           	/* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    Py8583_methods,             /* tp_methods */
    Py8583_members,             /* tp_members */
    Py8583_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Py8583_init,      /* tp_init */
    0,                         /* tp_alloc */
    Py8583_new,                 /* tp_new */
};

static PyMethodDef module_methods[] = {
	{"bcd2dec", (PyCFunction)Py8583_bcd2dec, METH_VARARGS, "BCD码转数字"},
	{"bcd2str", (PyCFunction)Py8583_bcd2str, METH_VARARGS, "BCD码转字符串"},
	{"dec2bcd", (PyCFunction)Py8583_dec2bcd, METH_VARARGS, "数字转BCD码"},
	{"str2bcd", (PyCFunction)Py8583_str2bcd, METH_VARARGS, "字符串转BCD码，字符串必须在0~9，a~f之内"},
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initPy8583(void)
{
    PyObject* m;

    if (PyType_Ready(&Py8583Type) < 0)
        return;

    m = Py_InitModule3("Py8583", module_methods,
                       "Example module that creates an extension type.");

    if (m == NULL)
      return;

    Py_INCREF(&Py8583Type);
    PyModule_AddObject(m, "Py8583", (PyObject *)&Py8583Type);
}
