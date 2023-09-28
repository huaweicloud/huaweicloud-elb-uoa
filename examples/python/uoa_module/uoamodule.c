/**
 * Copyright 2023 Huawei Cloud Computing Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "uoa_extra.h"
#include "uoa.h"


static PyObject *UoaErr;


static PyObject *uoa_get_real_address(PyObject *self, PyObject *args) {
    int socket_fd;
    int af;
    char *sip;
    int sport;
    int dport;
    if (!PyArg_ParseTuple(args, "iisii", &socket_fd, &af, &sip, &sport, &dport)) {
        return NULL;
    }

    int ret;
    struct uoa_param_map uoa_param;
    uint uoa_param_len = sizeof(uoa_param);
    char from[INET6_ADDRSTRLEN];

    memset(&uoa_param, 0, sizeof(uoa_param));
    uoa_param.af = af;
    if (inet_pton(af, sip, &uoa_param.saddr) != 1) {
        PyErr_SetString(UoaErr, "error in inet_pton");
        return NULL;
    }
    uoa_param.sport = htons(sport);
    uoa_param.dport = htons(dport);

    ret = getsockopt(socket_fd, IPPROTO_IP, UOA_SO_GET_LOOKUP, &uoa_param, &uoa_param_len);
    if (ret) {
        return Py_BuildValue("s", NULL);
    }

    if (inet_ntop(uoa_param.real_af, &uoa_param.real_saddr, from, sizeof(from)) == NULL) {
        PyErr_SetString(UoaErr, "error in inet_ntop");
        return NULL;
    }
    return Py_BuildValue("isi", uoa_param.real_af, from, ntohs(uoa_param.real_sport));
}

static PyMethodDef UoaMethods[] = {
        {"get_real_address", uoa_get_real_address, METH_VARARGS, "Get real address"},
        {NULL,               NULL,                 0,            NULL}
};

static struct PyModuleDef uoamodule = {
        PyModuleDef_HEAD_INIT,
        "uoa",
        NULL,
        -1,
        UoaMethods
};


PyMODINIT_FUNC PyInit_uoa(void) {
    PyObject *m;

    m = PyModule_Create(&uoamodule);
    if (m == NULL) {
        return NULL;
    }

    UoaErr = PyErr_NewException("uoa.error", NULL, NULL);
    Py_XINCREF(UoaErr);
    if (PyModule_AddObject(m, "error", UoaErr) < 0) {
        Py_XDECREF(UoaErr);
        Py_CLEAR(UoaErr);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}