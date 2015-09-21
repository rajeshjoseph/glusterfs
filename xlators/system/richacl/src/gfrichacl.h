/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef _RICHACL_H
#define _RICHACL_H

#include "xlator.h"
#include "common-utils.h"
#include "byte-order.h"
#include "glusterfs-acl.h"

typedef struct richacl_ {
        int             refcnt;
        int             flags;
        struct richacl *acl;
} richacl_t;

struct richacl_ctx {
        uid_t           uid;
        gid_t           gid;
        mode_t          perm;
        richacl_t      *acl_access;
};

struct richacl_conf {
        gf_lock_t         acl_lock;
        uid_t             super_uid;
};

richacl_t *gf_richacl_new (xlator_t *this);
richacl_t *gf_richacl_ref (xlator_t *this, richacl_t *acl);
void gf_richacl_unref (xlator_t *this, richacl_t *acl);
void gf_richacl_destroy (xlator_t *this, richacl_t *acl);
struct richacl_ctx *gf_richacl_ctx_get (inode_t *inode, xlator_t *this);
int gf_richacl_get (inode_t *inode, xlator_t *this, richacl_t **acl_access_p);
int gf_richacl_set (inode_t *inode, xlator_t *this, richacl_t *acl_access);

#endif /* !_RICHACL_H */
