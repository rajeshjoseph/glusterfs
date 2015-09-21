/*
  Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#include <errno.h>
#include <sys/richacl.h>

#include "xlator.h"
#include "glusterfs.h"

#include "gfrichacl.h"
#include "gfrichacl-xattr.h"
#include "gfrichacl-mem-types.h"


#define UINT64(ptr) ((uint64_t)((long)(ptr)))
#define PTR(num) ((void *)((long)(num)))


int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_richacl_mt_end + 1);

        if (ret != 0) {
                gf_log(this->name, GF_LOG_ERROR, "Memory accounting init"
                                "failed");
                return ret;
        }

        return ret;
}

static uid_t
r00t ()
{
        struct richacl_conf *conf = NULL;

        conf = THIS->private;

        return conf->super_uid;
}


static int
whitelisted_xattr (const char *key)
{
        if (NULL == key)
                return 0;

        if (strcmp (GF_RICHACL_ACL_KEY, key) == 0)
                return 1;

        if (strcmp (GF_RICHACL_SYS_ACL_KEY, key) == 0)
                return 1;

        return 0;
}


static int
frame_is_user (call_frame_t *frame, uid_t uid)
{
        return (frame->root->uid == uid);
}


static int
frame_is_super_user (call_frame_t *frame)
{
        int ret;

        ret = frame_is_user (frame, r00t());
        if (!ret)
                ret = frame_is_user (frame, 0);

        return ret;
}


int
frame_in_group (call_frame_t *frame, gid_t gid)
{
        int  i = 0;

        if (frame->root->gid == gid)
                return 1;

        for (i = 0; i < frame->root->ngrps; i++)
                if (frame->root->groups[i] == gid)
                        return 1;
        return 0;
}

static mode_t
gf_richacl_access_set_mode (richacl_t *acl, struct richacl_ctx *ctx)
{
        mode_t             mode = 0;
        return mode;
}


static int
sticky_permits (call_frame_t *frame, inode_t *parent, inode_t *inode)
{
        struct richacl_ctx     *par = NULL;
        struct richacl_ctx     *ctx = NULL;

        par = gf_richacl_ctx_get (parent, frame->this);
        ctx = gf_richacl_ctx_get (inode, frame->this);

        if (frame_is_super_user (frame))
                return 1;

        if (!(par->perm & S_ISVTX))
                return 1;

        if (frame_is_user (frame, par->uid))
                return 1;

        if (frame_is_user (frame, ctx->uid))
                return 1;

        return 0;
}

static int
gf_richacl_permits (call_frame_t *frame, inode_t *inode, int want)
{
        int                     verdict = 0;
        richacl_t              *acl = NULL;
        struct richacl_ctx     *ctx = NULL;
        int                     ret = -1;

        ctx = gf_richacl_ctx_get (inode, frame->this);
        if (!ctx)
                goto red;

        if (frame_is_super_user (frame))
                goto green;

        ret = gf_richacl_get (inode, frame->this, &acl);
        if (ret) {
                gf_log (frame->this->name, GF_LOG_ERROR,
                                "Failed to get richacl");
                goto out;
        }

green:
        verdict = 1;
        goto out;
red:
        verdict = 0;
out:
        if (acl)
                gf_richacl_unref (frame->this, acl);

        return verdict;
}


static int
acl_permits (call_frame_t *frame, inode_t *inode, int want)
{
        int                     verdict = 0;
        richacl_t              *acl = NULL;
        struct richacl_ctx     *ctx = NULL;

        ctx = gf_richacl_ctx_get (inode, frame->this);
        if (!ctx)
                goto red;

        if (frame_is_super_user (frame))
                goto green;

        gf_richacl_get (inode, frame->this, &acl);

green:
        verdict = 1;
        goto out;
red:
        verdict = 0;
out:
        if (acl)
                gf_richacl_unref (frame->this, acl);

        return verdict;
}


struct richacl_ctx *
gf_richacl_ctx_get (inode_t *inode, xlator_t *this)
{
        struct richacl_ctx     *ctx = NULL;
        uint64_t                int_ctx = 0;
        int                     ret = 0;

        ret = inode_ctx_get (inode, this, &int_ctx);
        if ((ret == 0) && (int_ctx))
                return PTR(int_ctx);

        ctx = GF_CALLOC (1, sizeof (*ctx), gf_richacl_mt_ctx_t);
        if (!ctx)
                return NULL;

        ret = inode_ctx_put (inode, this, UINT64 (ctx));

        return ctx;
}


int
__gf_richacl_set (inode_t *inode, xlator_t *this, richacl_t *acl)
{
        int                     ret = -1;
        struct richacl_ctx     *ctx = NULL;

        ctx = gf_richacl_ctx_get (inode, this);
        if (!ctx)
                goto out;

        ctx->acl_access = acl;

        ret = 0;
out:
        return ret;
}


int
__gf_richacl_get (inode_t *inode, xlator_t *this, richacl_t **acl_p)
{
        int                     ret = -1;
        struct richacl_ctx     *ctx = NULL;

        GF_VALIDATE_OR_GOTO (THIS->name, acl_p, out);
        *acl_p = NULL;

        ctx = gf_richacl_ctx_get (inode, this);
        if (NULL == ctx) {
                goto out;
        }

        *acl_p = ctx->acl_access;
out:
        return ret;
}


richacl_t *
gf_richacl_new (xlator_t *this)
{
        richacl_t       *acl = NULL;

        acl = GF_CALLOC (1, sizeof (*acl),
                        gf_richacl_mt_posix_ace_t);
        if (!acl)
                return NULL;

        gf_richacl_ref (this, acl);

        return acl;
}


richacl_t*
gf_richacl_ref (xlator_t *this, richacl_t *acl)
{
        struct richacl_conf  *conf = NULL;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                acl->refcnt++;
        }
        UNLOCK(&conf->acl_lock);

        return acl;
}


richacl_t *
gf_richacl_dup (xlator_t *this, richacl_t *acl)
{
        richacl_t       *dup = NULL;

        dup = gf_richacl_new (this);
        if (!dup)
                return NULL;

        return dup;
}

void
gf_richacl_destroy (xlator_t *this, richacl_t *richacl)
{
        GF_VALIDATE_OR_GOTO ("richacl", this, out);
        GF_VALIDATE_OR_GOTO (this->name, richacl, out);

        richacl_free (richacl->acl);
        GF_FREE (richacl);
out:
        return;
}


void
gf_richacl_unref (xlator_t *this, richacl_t *richacl)
{
        struct richacl_conf    *conf    = NULL;
        int                     refcnt  = 0;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                refcnt = --richacl->refcnt;
        }
        UNLOCK(&conf->acl_lock);

        if (!refcnt)
                gf_richacl_destroy (this, richacl);
}


int
gf_richacl_set (inode_t *inode, xlator_t *this, richacl_t *acl)
{
        int                     ret            = 0;
        int                     oldret         = 0;
        richacl_t              *old_access     = NULL;
        struct richacl_conf    *conf           = NULL;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                oldret = __gf_richacl_get (inode, this, &old_access);

                ret = __gf_richacl_set (inode, this, acl);
        }
        UNLOCK(&conf->acl_lock);

        if (ret)
                gf_log (this->name, GF_LOG_ERROR, "Failed to set richacl");

        if (oldret == 0 && old_access) {
                gf_richacl_unref (this, old_access);
        }

        return ret;
}


int
gf_richacl_get (inode_t *inode, xlator_t *this,
                richacl_t **acl_p)
{
        struct richacl_conf    *conf = NULL;
        int                     ret = 0;

        GF_VALIDATE_OR_GOTO ("richacl", this, out);
        GF_VALIDATE_OR_GOTO (this->name, inode, out);
        GF_VALIDATE_OR_GOTO (this->name, acl_p, out);

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                ret = __gf_richacl_get (inode, this, acl_p);
        }
        UNLOCK(&conf->acl_lock);

        if (ret) {
                gf_log (this->name, GF_LOG_DEBUG,
                                "Failed to get cached richacl");
#if 0
                *acl_p = richecl_get_file (path);
                if (*acl_p) {
                        ret = gf_richacl_set (inode, this, *acl_p);
                }
#endif //
        }

        if (NULL == *acl_p) {
                gf_log (this->name, GF_LOG_DEBUG,
                                "Failed to get richacl");
                ret = -1;
        }
out:

        return ret;
}


mode_t
gf_richacl_inherit_mode (richacl_t *acl, mode_t modein)
{
        mode_t                  newmode = modein;

        return newmode;
}


mode_t
gf_richacl_inherit (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode,
                int32_t umask, int is_dir)
{
        mode_t                 retmode = mode;

        return retmode;
}


mode_t
gf_richacl_inherit_dir (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode,
                int32_t umask)
{
        mode_t  retmode = 0;

        retmode = gf_richacl_inherit (this, loc, params, mode, umask, 1);

        return retmode;
}


mode_t
gf_richacl_inherit_file (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode,
                int32_t umask)
{
        mode_t  retmode = 0;

        retmode = gf_richacl_inherit (this, loc, params, mode, umask, 0);

        return retmode;
}

int
gf_richacl_ctx_update (inode_t *inode, xlator_t *this, struct iatt *buf)
{
        int                     ret = -1;
        struct richacl_ctx     *ctx = NULL;
        mode_t                  mode;

        ctx = gf_richacl_ctx_get (inode, this);
        if (NULL == ctx) {
                gf_log (this->name, GF_LOG_WARNING, "Failed to get ctx");
                goto out;
        }


        if (ctx->acl_access != NULL) {
                mode = st_mode_from_ia (buf->ia_prot, buf->ia_type);

                richacl_chmod (ctx->acl_access->acl, mode);
        }

        LOCK (&inode->lock);
        {
                ctx->uid  = buf->ia_uid;
                ctx->gid  = buf->ia_gid;
                ctx->perm = st_mode_from_ia (buf->ia_prot, buf->ia_type);
        }
        UNLOCK (&inode->lock);
        ret = 0;
out:
        return ret;
}


int
gf_richacl_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, inode_t *inode,
                struct iatt *buf, dict_t *xattr, struct iatt *postparent)
{
        int             ret = 0;
        richacl_t      *acl_access = NULL;
        richacl_t      *old_access = NULL;
        data_t         *data = NULL;
        dict_t         *my_xattr = NULL;

        if (op_ret != 0)
                goto unwind;

        ret = gf_richacl_get (inode, this, &old_access);

        data = dict_get (xattr, GF_RICHACL_ACL_KEY);
        if (!data)
                goto unwind;

        if (old_access &&
                        gf_richacl_matches_xattr (this, old_access, data->data,
                                data->len)) {
                acl_access = gf_richacl_ref (this, old_access);
        } else {
                acl_access = gf_richacl_from_xattr (this, data->data,
                                data->len);
        }

        gf_richacl_ctx_update (inode, this, buf);

        ret = gf_richacl_set (inode, this, acl_access);
        if (ret)
                gf_log (this->name, GF_LOG_WARNING,
                                "failed to set ACL in context");
unwind:
        my_xattr = frame->local;
        frame->local = NULL;
        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf, xattr,
                        postparent);

        if (acl_access)
                gf_richacl_unref (this, acl_access);
        if (old_access)
                gf_richacl_unref (this, old_access);
        if (my_xattr)
                dict_unref (my_xattr);

        return 0;
}


int
gf_richacl_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xattr)
{
        int     ret            = 0;
        dict_t *my_xattr       = NULL;

        /* lookup of / is always permitted */
        if (!loc->parent)
                goto green;

        if (gf_richacl_permits (frame, loc->parent, POSIX_ACL_EXECUTE))
                goto green;

        goto red;

green:
        if (xattr) {
                my_xattr = dict_ref (xattr);
        } else {
                my_xattr = dict_new ();
        }

        ret = dict_set_int8 (my_xattr, GF_RICHACL_ACL_KEY, 0);
        if (ret)
                gf_log (this->name, GF_LOG_WARNING, "failed to set key %s",
                                POSIX_ACL_ACCESS_XATTR);

        frame->local = my_xattr;
        STACK_WIND (frame, gf_richacl_lookup_cbk,
                        FIRST_CHILD (this), FIRST_CHILD (this)->fops->lookup,
                        loc, my_xattr);
        return 0;
red:
        STACK_UNWIND_STRICT (lookup, frame, -1, EACCES, NULL, NULL, NULL,
                        NULL);

        return 0;
}


int
gf_richacl_access (call_frame_t *frame, xlator_t *this, loc_t *loc, int mask,
                dict_t *xdata)
{
        int  op_ret = 0;
        int  op_errno = 0;
        int  perm = 0;
        int  mode = 0;
        int  is_fuse_call = 0;

        is_fuse_call = __is_fuse_call (frame);

        if (mask & R_OK)
                perm |= POSIX_ACL_READ;
        if (mask & W_OK)
                perm |= POSIX_ACL_WRITE;
        if (mask & X_OK)
                perm |= POSIX_ACL_EXECUTE;
        if (!mask) {
                goto unwind;
        }
        if (!perm) {
                op_ret = -1;
                op_errno = EINVAL;
                goto unwind;
        }

        if (is_fuse_call) {
                mode = acl_permits (frame, loc->inode, perm);
                if (mode) {
                        op_ret = 0;
                        op_errno = 0;
                } else {
                        op_ret = -1;
                        op_errno = EACCES;
                }
        } else {
                if (perm & POSIX_ACL_READ) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                                mode |= POSIX_ACL_READ;
                }

                if (perm & POSIX_ACL_WRITE) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                                mode |= POSIX_ACL_WRITE;
                }

                if (perm & POSIX_ACL_EXECUTE) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_EXECUTE))
                                mode |= POSIX_ACL_EXECUTE;
                }
        }

unwind:
        if (is_fuse_call)
                STACK_UNWIND_STRICT (access, frame, op_ret, op_errno, NULL);
        else
                STACK_UNWIND_STRICT (access, frame, 0, mode, NULL);
        return 0;
}


int
gf_richacl_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
        STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno, prebuf,
                        postbuf, xdata);

        return 0;
}


int
gf_richacl_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t off,
                dict_t *xdata)
{
        struct richacl_ctx *ctx = NULL;

        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                goto green;
        /* NFS does a truncate through SETATTR, the owner does not need write
         * * permissions for this. Group permissions and root are checked above.
         * */
        else if (frame->root->pid == NFS_PID) {
                ctx = gf_richacl_ctx_get (loc->inode, frame->this);

                if (ctx && frame_is_user (frame, ctx->uid))
                        goto green;
        }

        /* fail by default */
        STACK_UNWIND_STRICT (truncate, frame, -1, EACCES, NULL, NULL, NULL);
        return 0;

green:
        STACK_WIND (frame, gf_richacl_truncate_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->truncate,
                        loc, off, xdata);
        return 0;
}


int
gf_richacl_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, fd_t *fd, dict_t *xdata)
{
        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);

        return 0;
}


int
gf_richacl_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int flags,
                fd_t *fd, dict_t *xdata)
{
        int perm = 0;

        switch (flags & O_ACCMODE) {
                case O_RDONLY:
                        perm = POSIX_ACL_READ;

                        /* If O_FMODE_EXEC is present, its good enough
                         * to have '--x' perm, and its not covered in
                         * O_ACCMODE bits */
                        if (flags & O_FMODE_EXEC)
                                perm = POSIX_ACL_EXECUTE;

                        break;
                case O_WRONLY:
                case O_APPEND:
                case O_TRUNC:
                        perm = POSIX_ACL_WRITE;
                        break;
                case O_RDWR:
                        perm = POSIX_ACL_READ|POSIX_ACL_WRITE;
                        break;
        }

        if (acl_permits (frame, loc->inode, perm))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_open_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->open,
                        loc, flags, fd, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (open, frame, -1, EACCES, NULL, xdata);
        return 0;
}


int
gf_richacl_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, struct iovec *vector,
                int count, struct iatt *stbuf, struct iobref *iobref,
                dict_t *xdata)
{
        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno, vector, count,
                        stbuf, iobref, xdata);
        return 0;
}


int
gf_richacl_readv (call_frame_t *frame, xlator_t *this, fd_t *fd,
                size_t size, off_t offset, uint32_t flags, dict_t *xdata)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, gf_richacl_readv_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->readv,
                        fd, size, offset, flags, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (readv, frame, -1, EACCES, NULL, 0, NULL, NULL, xdata);
        return 0;
}


int
gf_richacl_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                struct iatt *prebuf, struct iatt *postbuf, dict_t *xdata)
{
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno,
                        prebuf, postbuf, xdata);
        return 0;
}


int
gf_richacl_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
                struct iovec *vector, int count, off_t offset,
                uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, gf_richacl_writev_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->writev,
                        fd, vector, count, offset, flags, iobref, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (writev, frame, -1, EACCES, NULL, NULL, xdata);
        return 0;
}



int
gf_richacl_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
        STACK_UNWIND_STRICT (ftruncate, frame, op_ret, op_errno,
                        prebuf, postbuf, xdata);
        return 0;
}


int
gf_richacl_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd,
                off_t offset, dict_t *xdata)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, gf_richacl_ftruncate_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->ftruncate,
                        fd, offset, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (ftruncate, frame, -1, EACCES, NULL, NULL, xdata);
        return 0;
}


int
gf_richacl_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, fd_t *fd, dict_t *xdata)
{
        STACK_UNWIND_STRICT (opendir, frame, op_ret, op_errno, fd, xdata);

        return 0;
}


int
gf_richacl_opendir (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd, dict_t *xdata)
{
        if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_opendir_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->opendir,
                        loc, fd, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (opendir, frame, -1, EACCES, NULL, xdata);
        return 0;
}


int
gf_richacl_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, inode_t *inode, struct iatt *buf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, buf);

unwind:
        STACK_UNWIND_STRICT (mkdir, frame, op_ret, op_errno, inode, buf,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_mkdir (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
                mode_t umask, dict_t *xdata)
{
        mode_t   newmode = 0;

        newmode = mode;
        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        newmode = gf_richacl_inherit_dir (this, loc, xdata, mode, umask);

        STACK_WIND (frame, gf_richacl_mkdir_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->mkdir,
                        loc, newmode, umask, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (mkdir, frame, -1, EACCES, NULL, NULL, NULL, NULL,
                        NULL);
        return 0;
}


int
gf_richacl_mknod_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, inode_t *inode, struct iatt *buf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, buf);

unwind:
        STACK_UNWIND_STRICT (mknod, frame, op_ret, op_errno, inode, buf,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
                dev_t rdev, mode_t umask, dict_t *xdata)
{
        mode_t  newmode = 0;

        newmode = mode;
        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        newmode = gf_richacl_inherit_file (this, loc, xdata, mode, umask);

        STACK_WIND (frame, gf_richacl_mknod_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->mknod,
                        loc, newmode, rdev, umask, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (mknod, frame, -1, EACCES, NULL, NULL, NULL, NULL,
                        NULL);
        return 0;
}


int
gf_richacl_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, fd_t *fd, inode_t *inode,
                struct iatt *buf, struct iatt *preparent,
                struct iatt *postparent, dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, buf);

unwind:
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, buf,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int flags,
                mode_t mode, mode_t umask, fd_t *fd, dict_t *xdata)
{
        mode_t  newmode = 0;

        newmode = mode;
        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        newmode = gf_richacl_inherit_file (this, loc, xdata, mode, umask);

        STACK_WIND (frame, gf_richacl_create_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->create,
                        loc, flags, newmode, umask, fd, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (create, frame, -1, EACCES, NULL, NULL, NULL,
                        NULL, NULL, NULL);
        return 0;
}


int
gf_richacl_symlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, inode_t *inode,
                struct iatt *buf, struct iatt *preparent,
                struct iatt *postparent, dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, buf);

unwind:
        STACK_UNWIND_STRICT (symlink, frame, op_ret, op_errno, inode, buf,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_symlink (call_frame_t *frame, xlator_t *this, const char *linkname,
                loc_t *loc, mode_t umask, dict_t *xdata)
{
        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_symlink_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->symlink,
                        linkname, loc, umask, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (symlink, frame, -1, EACCES, NULL, NULL, NULL,
                        NULL, xdata);
        return 0;
}


int
gf_richacl_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, struct iatt *preparent,
                struct iatt *postparent, dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (unlink, frame, op_ret, op_errno,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc, int xflag,
                dict_t *xdata)
{
        if (!sticky_permits (frame, loc->parent, loc->inode))
                goto red;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_unlink_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->unlink,
                        loc, xflag, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (unlink, frame, -1, EACCES, NULL, NULL, xdata);
        return 0;
}


int
gf_richacl_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                struct iatt *preparent, struct iatt *postparent, dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (rmdir, frame, op_ret, op_errno,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc, int flags, dict_t *xdata)
{
        if (!sticky_permits (frame, loc->parent, loc->inode))
                goto red;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_rmdir_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->rmdir,
                        loc, flags, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (rmdir, frame, -1, EACCES, NULL, NULL, xdata);
        return 0;
}


int
gf_richacl_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, struct iatt *buf,
                struct iatt *preoldparent, struct iatt *postoldparent,
                struct iatt *prenewparent, struct iatt *postnewparent,
                dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (rename, frame, op_ret, op_errno, buf,
                        preoldparent, postoldparent,
                        prenewparent, postnewparent, xdata);
        return 0;
}


int
gf_richacl_rename (call_frame_t *frame, xlator_t *this, loc_t *old, loc_t *new, dict_t *xdata)
{
        if (!acl_permits (frame, old->parent, POSIX_ACL_WRITE))
                goto red;

        if (!acl_permits (frame, new->parent, POSIX_ACL_WRITE))
                goto red;

        if (!sticky_permits (frame, old->parent, old->inode))
                goto red;

        if (new->inode) {
                if (!sticky_permits (frame, new->parent, new->inode))
                        goto red;
        }

        STACK_WIND (frame, gf_richacl_rename_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->rename,
                        old, new, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (rename, frame, -1, EACCES, NULL, NULL, NULL, NULL,
                        NULL, NULL);
        return 0;
}


int
gf_richacl_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, inode_t *inode, struct iatt *buf,
                struct iatt *preparent, struct iatt *postparent, dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (link, frame, op_ret, op_errno, inode, buf,
                        preparent, postparent, xdata);
        return 0;
}


int
gf_richacl_link (call_frame_t *frame, xlator_t *this, loc_t *old, loc_t *new, dict_t *xdata)
{
        struct richacl_ctx *ctx = NULL;
        int                   op_errno = 0;

        ctx = gf_richacl_ctx_get (old->inode, this);
        if (!ctx) {
                op_errno = EIO;
                goto red;
        }

        if (!acl_permits (frame, new->parent, POSIX_ACL_WRITE)) {
                op_errno = EACCES;
                goto red;
        }

        if (!sticky_permits (frame, new->parent, new->inode)) {
                op_errno = EACCES;
                goto red;
        }

        STACK_WIND (frame, gf_richacl_link_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->link,
                        old, new, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (link, frame, -1, op_errno, NULL, NULL, NULL, NULL, xdata);

        return 0;
}


int
gf_richacl_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, gf_dirent_t *entries,
                dict_t *xdata)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, entries, xdata);
        return 0;
}


int
gf_richacl_readdir (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                off_t offset, dict_t *xdata)
{
        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_readdir_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->readdir,
                        fd, size, offset, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (readdir, frame, -1, EACCES, NULL, xdata);

        return 0;
}


int
gf_richacl_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, gf_dirent_t *entries,
                dict_t *xdata)
{
        gf_dirent_t    *entry       = NULL;
        richacl_t      *acl_access  = NULL;
        data_t         *data        = NULL;
        int             ret         = 0;

        if (op_ret <= 0)
                goto unwind;

        list_for_each_entry (entry, &entries->list, list) {
                /* Update the inode ctx */
                if (!entry->dict || !entry->inode)
                        continue;

                ret = gf_richacl_get (entry->inode, this, &acl_access);

                data = dict_get (entry->dict, GF_RICHACL_ACL_KEY);
                if (!data)
                        goto acl_set;

                if (acl_access &&
                                gf_richacl_matches_xattr (this, acl_access, data->data,
                                        data->len))
                        goto acl_set;

                if (acl_access)
                        gf_richacl_unref(this, acl_access);

                acl_access = gf_richacl_from_xattr (this, data->data,
                                data->len);

acl_set:
                gf_richacl_ctx_update (entry->inode, this, &entry->d_stat);

                ret = gf_richacl_set (entry->inode, this, acl_access);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                        "failed to set ACL in context");

                if (acl_access)
                        gf_richacl_unref(this, acl_access);
        }

unwind:
        STACK_UNWIND_STRICT (readdirp, frame, op_ret, op_errno, entries, xdata);
        return 0;
}


int
gf_richacl_readdirp (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                off_t offset, dict_t *dict)
{
        int ret = 0;
        dict_t *alloc_dict = NULL;

        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        if (!dict)
                dict = alloc_dict = dict_new ();

        if (dict) {
                ret = dict_set_int8 (dict, GF_RICHACL_ACL_KEY, 0);
                if (ret)
                        gf_log (this->name, GF_LOG_WARNING,
                                        "failed to set key %s",
                                        POSIX_ACL_ACCESS_XATTR);

        }

        STACK_WIND (frame, gf_richacl_readdirp_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readdirp,
                    fd, size, offset, dict);

	if (alloc_dict)
	dict_unref (alloc_dict);
       return 0;
red:
       STACK_UNWIND_STRICT (readdirp, frame, -1, EACCES, NULL, NULL);

       return 0;
}


int
setattr_scrutiny (call_frame_t *frame, inode_t *inode, struct iatt *buf,
                int valid)
{
        struct richacl_ctx   *ctx = NULL;

        if (frame_is_super_user (frame))
                return 0;

        ctx = gf_richacl_ctx_get (inode, frame->this);
        if (!ctx)
                return EIO;

        if (valid & GF_SET_ATTR_MODE) {
                /*
                 * The effective UID of the calling process must match the  owner  of  the
                 * file,  or  the  process  must  be  privileged
                 * */
                if (!frame_is_user (frame, ctx->uid))
                        return EPERM;
                /*
                 * If the calling process is not privileged  (Linux:  does  not  have  the
                 * CAP_FSETID  capability),  and  the group of the file does not match the
                 * effective group ID of the process or one  of  its  supplementary  group
                 * IDs,  the  S_ISGID  bit  will be turned off, but this will not cause an
                 * error to be returned.
                 *
                 * */
                if (!frame_in_group (frame, ctx->gid))
                        buf->ia_prot.sgid = 0;
        }

        if (valid & (GF_SET_ATTR_ATIME | GF_SET_ATTR_MTIME)) {
                /*
                 * Changing timestamps is permitted when: either the process has appropri?
                 * ate  privileges,  or  the  effective  user ID equals the user ID of the
                 * file, or times is NULL and the process has  write  permission  for  the
                 * file.
                 * */
                if (!frame_is_user (frame, ctx->uid) &&
                                !acl_permits (frame, inode, POSIX_ACL_WRITE))
                        return EACCES;
        }

        if (valid & GF_SET_ATTR_UID) {
                if ((!frame_is_super_user (frame)) &&
                                (buf->ia_uid != ctx->uid))
                        return EPERM;
        }

        if (valid & GF_SET_ATTR_GID) {
                if (!frame_is_user (frame, ctx->uid))
                        return EPERM;
                if (!frame_in_group (frame, buf->ia_gid))
                        return EPERM;
        }

        return 0;
}


int
gf_richacl_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                struct iatt *prebuf, struct iatt *postbuf, dict_t *xdata)
{
        inode_t   *inode = NULL;

        inode = frame->local;
        frame->local = NULL;

        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, postbuf);

unwind:
        STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno, prebuf,
                        postbuf, xdata);
        return 0;
}


int
gf_richacl_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                struct iatt *buf, int valid, dict_t *xdata)
{
        int  op_errno = 0;

        op_errno = setattr_scrutiny (frame, loc->inode, buf, valid);

        if (op_errno)
                goto red;

        frame->local = loc->inode;

        STACK_WIND (frame, gf_richacl_setattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->setattr,
                        loc, buf, valid, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (setattr, frame, -1, op_errno, NULL, NULL, xdata);

        return 0;
}


int
gf_richacl_fsetattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                struct iatt *prebuf, struct iatt *postbuf, dict_t *xdata)
{
        inode_t   *inode = NULL;

        inode = frame->local;
        frame->local = NULL;

        if (op_ret != 0)
                goto unwind;

        gf_richacl_ctx_update (inode, this, postbuf);

unwind:
        STACK_UNWIND_STRICT (fsetattr, frame, op_ret, op_errno, prebuf,
                        postbuf, xdata);
        return 0;
}


int
gf_richacl_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                struct iatt *buf, int valid, dict_t *xdata)
{
        int  op_errno = 0;

        op_errno = setattr_scrutiny (frame, fd->inode, buf, valid);

        if (op_errno)
                goto red;

        frame->local = fd->inode;

        STACK_WIND (frame, gf_richacl_fsetattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->fsetattr,
                        fd, buf, valid, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (fsetattr, frame, -1, EACCES, NULL, NULL, xdata);

        return 0;
}


int
setxattr_scrutiny (call_frame_t *frame, inode_t *inode, dict_t *xattr)
{
        struct richacl_ctx   *ctx = NULL;
        int                     found = 0;

        if (frame_is_super_user (frame))
                return 0;

        ctx = gf_richacl_ctx_get (inode, frame->this);
        if (!ctx)
                return EIO;

        if (dict_get (xattr, GF_RICHACL_ACL_KEY)) {
                found = 1;
                if (!frame_is_user (frame, ctx->uid))
                        return EPERM;
        }


        if (!found && !acl_permits (frame, inode, POSIX_ACL_WRITE))
                return EACCES;

        return 0;
}


richacl_t*
gf_richacl_xattr_update (xlator_t *this, inode_t *inode, dict_t *xattr,
                char *name, richacl_t *old)
{
        richacl_t      *acl = NULL;
        data_t         *data = NULL;

        data = dict_get (xattr, name);
        if (data) {
                acl = gf_richacl_from_xattr (this, data->data,
                                data->len);
        }

        if (!acl && old)
                acl = gf_richacl_ref (this, old);

        return acl;
}


int
gf_richacl_setxattr_update (xlator_t *this, inode_t *inode, dict_t *xattr)
{
        richacl_t              *acl_access = NULL;
        richacl_t              *old_access = NULL;
        char                   *acl_value = NULL;
        struct richacl_ctx     *ctx = NULL;
        int                     ret = 0;

        ctx = gf_richacl_ctx_get (inode, this);
        if (!ctx)
                return -1;

        ret = gf_richacl_get (inode, this, &old_access);
        if (ret)
                gf_log (this->name, GF_LOG_DEBUG, "Old acl not present");

        ret = dict_get_str (xattr, GF_RICHACL_SYS_ACL_KEY, &acl_value);
        if (!ret) {
                ret = dict_set_dynstr_with_alloc (xattr,
                                GF_RICHACL_ACL_KEY,
                                acl_value);
                if (ret) {
                        gf_log (this->name, GF_LOG_ERROR, "Failed to set "
                                        "%s key in dictionary", GF_RICHACL_ACL_KEY);
                        goto out;
                }
        }

        acl_access = gf_richacl_xattr_update (this, inode, xattr,
                        GF_RICHACL_ACL_KEY,
                        old_access);

        ret = gf_richacl_set (inode, this, acl_access);

        if (acl_access && acl_access != old_access) {
                gf_richacl_access_set_mode (acl_access, ctx);
        }

out:
        if (acl_access)
                gf_richacl_unref (this, acl_access);
        if (old_access)
                gf_richacl_unref (this, old_access);

        return ret;
}


int
gf_richacl_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, dict_t *xdata)
{
        STACK_UNWIND_STRICT (setxattr, frame, op_ret, op_errno, xdata);

        return 0;
}


int
gf_richacl_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                dict_t *xattr, int flags, dict_t *xdata)
{
        int  op_errno = 0;

        op_errno = setxattr_scrutiny (frame, loc->inode, xattr);

        if (op_errno != 0)
                goto red;

        gf_richacl_setxattr_update (this, loc->inode, xattr);

        STACK_WIND (frame, gf_richacl_setxattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr,
                        loc, xattr, flags, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (setxattr, frame, -1, op_errno, xdata);

        return 0;
}


int
gf_richacl_fsetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, dict_t *xdata)
{
        STACK_UNWIND_STRICT (fsetxattr, frame, op_ret, op_errno, xdata);

        return 0;
}


int
gf_richacl_fsetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                dict_t *xattr, int flags, dict_t *xdata)
{
        int  op_errno = 0;

        op_errno = setxattr_scrutiny (frame, fd->inode, xattr);

        if (op_errno != 0)
                goto red;

        gf_richacl_setxattr_update (this, fd->inode, xattr);

        STACK_WIND (frame, gf_richacl_fsetxattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->fsetxattr,
                        fd, xattr, flags, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (fsetxattr, frame, -1, op_errno, xdata);

        return 0;
}


int
gf_richacl_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, dict_t *xattr, dict_t *xdata)
{
        STACK_UNWIND_STRICT (getxattr, frame, op_ret, op_errno, xattr, xdata);

        return 0;
}


int
gf_richacl_getxattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                const char *name, dict_t *xdata)
{
        if (whitelisted_xattr (name))
                goto green;

        if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, gf_richacl_getxattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->getxattr,
                        loc, GF_RICHACL_ACL_KEY, xdata);
        return 0;

red:
        STACK_UNWIND_STRICT (getxattr, frame, -1, EACCES, NULL, xdata);

        return 0;
}


int
gf_richacl_fgetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, dict_t *xattr, dict_t *xdata)
{
        STACK_UNWIND_STRICT (fgetxattr, frame, op_ret, op_errno, xattr, xdata);

        return 0;
}


int
gf_richacl_fgetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                const char *name, dict_t *xdata)
{
        if (whitelisted_xattr (name))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_fgetxattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->fgetxattr,
                        fd, name, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (fgetxattr, frame, -1, EACCES, NULL, xdata);

        return 0;
}


int
gf_richacl_removexattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno, dict_t *xdata)
{
        STACK_UNWIND_STRICT (removexattr, frame, op_ret, op_errno, xdata);

        return 0;
}


int
gf_richacl_removexattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                const char *name, dict_t *xdata)
{
        struct  richacl_ctx    *ctx = NULL;
        int                     op_errno = EACCES;

        if (frame_is_super_user (frame))
                goto green;

        ctx = gf_richacl_ctx_get (loc->inode, this);
        if (!ctx) {
                op_errno = EIO;
                goto red;
        }

        if (whitelisted_xattr (name)) {
                if (!frame_is_user (frame, ctx->uid)) {
                        op_errno = EPERM;
                        goto red;
                }
        }

        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, gf_richacl_removexattr_cbk,
                        FIRST_CHILD(this), FIRST_CHILD(this)->fops->removexattr,
                        loc, name, xdata);
        return 0;
red:
        STACK_UNWIND_STRICT (removexattr, frame, -1, op_errno, xdata);

        return 0;
}


int
gf_richacl_forget (xlator_t *this, inode_t *inode)
{
        struct richacl_ctx *ctx = NULL;

        ctx = gf_richacl_ctx_get (inode, this);
        if (!ctx)
                goto out;

        if (ctx->acl_access)
                gf_richacl_unref (this, ctx->acl_access);

        GF_FREE (ctx);
out:
        return 0;
}


int
reconfigure (xlator_t *this, dict_t *options)
{
        struct richacl_conf *conf = NULL;

        conf = this->private;

        GF_OPTION_RECONF ("super-uid", conf->super_uid, options, uint32, err);

        return 0;
err:
        return -1;
}


int
init (xlator_t *this)
{
        struct richacl_conf   *conf = NULL;

        conf = GF_CALLOC (1, sizeof (*conf), gf_richacl_mt_conf_t);
        if (!conf) {
                gf_log (this->name, GF_LOG_ERROR,
                                "out of memory");
                return -1;
        }

        LOCK_INIT (&conf->acl_lock);

        this->private = conf;

        GF_OPTION_INIT ("super-uid", conf->super_uid, uint32, err);

        return 0;
err:
        return -1;
}


int
fini (xlator_t *this)
{
        struct richacl_conf   *conf = NULL;

        conf = this->private;
        if (!conf)
                return 0;
        this->private = NULL;

        LOCK_DESTROY (&conf->acl_lock);

        GF_FREE (conf);

        return 0;
}


struct xlator_fops fops = {
        .lookup           = gf_richacl_lookup,
        .open             = gf_richacl_open,
#if FD_MODE_CHECK_IS_IMPLEMENTED
        .readv            = gf_richacl_readv,
        .writev           = gf_richacl_writev,
        .ftruncate        = gf_richacl_ftruncate,
        .fsetattr         = gf_richacl_fsetattr,
        .fsetxattr        = gf_richacl_fsetxattr,
        .fgetxattr        = gf_richacl_fgetxattr,
#endif
        .access           = gf_richacl_access,
        .truncate         = gf_richacl_truncate,
        .mkdir            = gf_richacl_mkdir,
        .mknod            = gf_richacl_mknod,
        .create           = gf_richacl_create,
        .symlink          = gf_richacl_symlink,
        .unlink           = gf_richacl_unlink,
        .rmdir            = gf_richacl_rmdir,
        .rename           = gf_richacl_rename,
        .link             = gf_richacl_link,
        .opendir          = gf_richacl_opendir,
        .readdir          = gf_richacl_readdir,
        .readdirp         = gf_richacl_readdirp,
        .setattr          = gf_richacl_setattr,
        .setxattr         = gf_richacl_setxattr,
        .getxattr         = gf_richacl_getxattr,
        .removexattr      = gf_richacl_removexattr,
};


struct xlator_cbks cbks = {
        .forget           = gf_richacl_forget
};


struct volume_options options[] = {
        { .key  = {"super-uid"},
                .type = GF_OPTION_TYPE_INT,
                .default_value = "0",
                .description = "UID to be treated as super user's id instead of 0",
        },
        { .key = {NULL} },
};
