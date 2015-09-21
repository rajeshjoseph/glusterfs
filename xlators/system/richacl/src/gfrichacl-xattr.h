/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __RICHACL_XATTR_H
#define __RICHACL_XATTR_H

#include "common-utils.h"
#include "gfrichacl.h"
#include "glusterfs.h"
#include "glusterfs-acl.h"

richacl_t *gf_richacl_from_xattr (xlator_t *this, const char *buf, int size);

int gf_richacl_to_xattr (xlator_t *this, richacl_t *acl, char *buf, int size);

int gf_richacl_matches_xattr (xlator_t *this, richacl_t *acl, const char *buf, int size);


#endif /* !__RICHACL_XATTR_H*/
