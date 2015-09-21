/*
   Copyright (c) 2011-2013 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#include <stdio.h>
#include <stdlib.h>

#include "gfrichacl.h"
#include "gfrichacl-xattr.h"
#include "gfrichacl-mem-types.h"

void
gf_richacl_error (const char *fmt, ...)
{
        va_list args;
        va_start (args, fmt);
        gf_log (THIS->name, GF_LOG_WARNING, fmt, args);
        va_end (args);
}

richacl_t *
gf_richacl_from_xattr (xlator_t *this, const char *xattr_buf, int xattr_size)
{
        struct richacl *acl = NULL;
        richacl_t *gfacl = NULL;
        int flags = 0;

        acl = richacl_from_text (xattr_buf, &flags, gf_richacl_error);
        if (NULL == acl) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to convert to "
                        "richacl");
                goto out;
        }

        gfacl = GF_CALLOC (1, sizeof (*gfacl), gf_richacl_mt_acl);
        if (NULL == gfacl)
                goto out;

        gfacl->acl = acl;

out:
        return gfacl;
}


int
gf_richacl_to_xattr (xlator_t *this, richacl_t *acl, char *xattr_buf,
                    int xattr_size)
{
        int ret = -1;

        GF_VALIDATE_OR_GOTO (this->name, acl, out);
        GF_VALIDATE_OR_GOTO (this->name, xattr_buf, out);


        xattr_buf = richacl_to_text (acl->acl, acl->flags);
out:
        return ret;
}


int
gf_richacl_matches_xattr (xlator_t *this, richacl_t *acl, const char *buf,
                         int size)
{
        richacl_t  *acl2 = NULL;
        int                ret = 1;

        acl2 = gf_richacl_from_xattr (this, buf, size);
        if (!acl2)
                return 0;

        gf_richacl_destroy (this, acl2);

        return ret;
}

